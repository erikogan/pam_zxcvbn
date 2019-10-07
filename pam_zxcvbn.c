#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <zxcvbn/zxcvbn.h>

// TODO: translate
/* #include <libintl.h>
#define _(str) gettext(str) */

// Define which PAM functions we support (and let the header define prototypes)
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#define DEBUG_FLAG  1
#define MIN_TRIES   1
#define MIN_SCORE   3
#define MIN_ENTROPY -1.0L

#define LOG_WARN    LOG_WARNING

#define PATH_PASSWD "/etc/passwd"

struct module_options {
  int debug;
  int tries;
  int min_score;
  double min_entropy;
  int enforce_for_root;
  int local_users_only;
  const char *local_users_file;
};

static void debug_log(pam_handle_t *pamh, struct module_options *opt, int level, char *fmt, ...);
static void parse_arguments(pam_handle_t *pamh, struct module_options *opt, int argc, const char **argv);
static int check_local_user(pam_handle_t *pamh, struct module_options *opt, const char *user);
static int zxcvbn_score(double entropy);

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  /* As long as we’re linked, everything should be fine */
  int init_status = ZxcvbnInit();
  struct module_options options;
  int retval;
  const char *user;
  int tries;

  if (flags & PAM_PRELIM_CHECK) {
    if (init_status) {
      return PAM_SUCCESS;
    } else {
      return PAM_TRY_AGAIN;
    }
  }

  memset(&options, 0, sizeof(options));

  if (!(flags & PAM_UPDATE_AUTHTOK)) {
    parse_arguments(pamh, &options, argc, argv);
    debug_log(pamh, &options, LOG_NOTICE, "UNKNOWN flags setting %02X", flags);
    return PAM_SERVICE_ERR;
  }

  options.tries = MIN_TRIES;
  options.min_score = MIN_SCORE;
  options.min_entropy = MIN_ENTROPY;
  options.local_users_file = PATH_PASSWD;

  parse_arguments(pamh, &options, argc, argv);

  retval = pam_get_user(pamh, &user, NULL);

  if (retval != PAM_SUCCESS || user == NULL) {
    debug_log(pamh, &options, LOG_ERR, "Cannot get username");
    return PAM_AUTHTOK_ERR;
  }

  // TODO: Maybe add this to the user dict later?
  // retval = pam_get_item(pamh, PAM_OLDAUTHTOK, &oldtoken);
  // if (retval != PAM_SUCCESS) {
  //   debug_log(pamh, &options, LOG_ERR, "Can not get old passwd")
  //   oldtoken = NULL;
  // }

  for(tries = 0 ; tries < options.tries ; tries++) {
    const char *new_token = NULL;
    // TODO: Use matches
    // ZxcMatch_t *matches;
    double entropy;

    retval = pam_get_authtok_noverify(pamh, &new_token, NULL);

    if (retval != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "pam_get_authtok_noverify returned an error: %s", pam_strerror(pamh, retval));
      continue;
    } else if (new_token == NULL) { /* user aborted password change */
      return PAM_AUTHTOK_ERR;
    }

    if (options.local_users_only && check_local_user(pamh, &options, user) == 0) {
      /* skip the check if a non-local user */
      retval = 0;
    } else {
      // TODO: Add a user dictionary
      // TODO: Use matches
      // entropy = ZxcvbnMatch(new_token, NULL, &matches);
      entropy = ZxcvbnMatch(new_token, NULL, NULL);
      debug_log(pamh, &options, LOG_INFO, "ZxcvbnMatch returned: %lf", entropy);
    }

    int bad_password = 0;

    if (options.min_entropy > 0) {
      if (entropy < options.min_entropy) {
        bad_password = 1;
        debug_log(pamh, &options, LOG_INFO, "Bad password: inssufficient entropy: %lf < %lf", entropy,
                  options.min_entropy);
        pam_error(pamh, "BAD PASSWORD. Try adding some words");
      }
    } else {
      int score = zxcvbn_score(entropy);
      debug_log(pamh, &options, LOG_DEBUG, "Password Score: %d", score);
      if (score < options.min_score) {
        bad_password = 1;
        debug_log(pamh, &options, LOG_INFO, "Bad password: score %d < %d", score, options.min_score);
        pam_error(pamh, "BAD PASSWORD. Try adding some words");
      }
    }

    // TODO: Use matches
    // ZxcvbnFreeInfo(matches);

    if (bad_password && (getuid() || options.enforce_for_root || (flags & PAM_CHANGE_EXPIRED_AUTHTOK))) {
      pam_set_item(pamh, PAM_AUTHTOK, NULL);
      retval = PAM_AUTHTOK_ERR;
      continue;
    }

    retval = pam_get_authtok_verify(pamh, &new_token, NULL);
    if (retval != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "pam_get_authtok_verify returned an error: %s", pam_strerror(pamh, retval));
      pam_set_item(pamh, PAM_AUTHTOK, NULL);
      continue;
    } else if (new_token == NULL) {      /* user aborted password change */
      return PAM_AUTHTOK_ERR;
    }

    return PAM_SUCCESS;
  }

  pam_set_item (pamh, PAM_AUTHTOK, NULL);

  /* if we have only one try, we can use the real reason,
   * else say that there were too many tries. */
  if (options.tries > 1)
    return PAM_MAXTRIES;
  else
    return retval;
}

static int zxcvbn_score(double entropy) {
  double guesses = pow(2.0L, entropy);
  double lg10 = log10(guesses);

  if (lg10 < 3.0L)
    return 0;
  if (lg10 < 6.0L)
    return 1;
  if (lg10 < 8.0L)
    return 2;
  if (lg10 < 10.0L)
    return 3;

  return 4;
}

static int check_local_user(pam_handle_t *pamh, struct module_options *opt, const char *user) {
  struct passwd pw, *pwp;
  char buf[4096];
  int found = 0;
  FILE *fp;
  int errn;

  fp = fopen(opt->local_users_file, "r");
  if (fp == NULL) {
    pam_syslog(pamh, LOG_ERR, "unable to open local password file %s: %s", opt->local_users_file,
               pam_strerror(pamh, errno));
    return -1;
  }

  for (;;) {
    errn = fgetpwent_r(fp, &pw, buf, sizeof (buf), &pwp);
    if (errn == ERANGE) {
      pam_syslog(pamh, LOG_WARNING, "%s contains very long lines; corrupted?", PATH_PASSWD);
      /* we can continue here as next call will read further */
      continue;
    }

    if (errn != 0)
      break;

    if (strcmp(pwp->pw_name, user) == 0) {
      found = 1;
      break;
    }
  }

  fclose (fp);

  if (errn != 0 && errn != ENOENT) {
    pam_syslog(pamh, LOG_ERR, "unable to enumerate local accounts: %s", pam_strerror(pamh, errn));
    return -1;
  } else {
    return found;
  }
}

static void parse_tries(pam_handle_t *pamh, struct module_options *opt, const char *arg) {
  char *end = NULL;

  opt->tries = strtol(arg, &end, 10);

  if (!end || (opt->tries < MIN_TRIES)) {
    debug_log(pamh, opt, LOG_WARN, "Invalid try value: %s", arg);
    opt->tries = MIN_TRIES;
  }
}

static void parse_arguments(pam_handle_t *pamh, struct module_options *opt, int argc, const char **argv) {
  int entropy_and_score = 0;

  for (; argc-- > 0; ++argv) {
    char *end = NULL;

    if (!strcmp(*argv, "debug")){
      opt->debug |= DEBUG_FLAG;
    } else if (!strncmp(*argv, "tries=", 6)) {
      parse_tries(pamh, opt, *argv + 6);
    } else if (!strncmp(*argv, "retry=", 6)) { /* Keep this for backward compatibility, but its name is confusing */
      parse_tries(pamh, opt, *argv + 6);
    } else if (!strncmp(*argv, "min_entropy=", 12)) {
      opt->min_entropy = strtod(*argv + 12, &end);
      if(!end || (opt->min_entropy < 0.0L)) {
        debug_log(pamh, opt, LOG_WARN, "Invalid min_entropy value: %s", *argv + 12);
        opt->min_entropy = MIN_ENTROPY;
      } else {
        entropy_and_score |= 1;
      }
      end = NULL;
    } else if (!strncmp(*argv, "min_score=", 10)) {
      opt->min_score = strtod(*argv + 10, &end);
      if(!end || (opt->min_score <= 0)) {
        debug_log(pamh, opt, LOG_WARN, "Invalid min_score value: %s", *argv + 10);
        opt->min_score = MIN_ENTROPY;
      } else {
        entropy_and_score |= 2;
      }
      end = NULL;
    } else if (!strncmp(*argv, "enforce_for_root", 16)) {
      opt->enforce_for_root = 1;
    } else if (!strncmp(*argv, "local_users_only", 16)) {
      opt->local_users_only = 1;
    } else if (!strncmp(*argv, "local_users_file=", 17)) {
      opt->local_users_file = *argv + 17;
    } else if (!strncmp(*argv, "type=", 5)) {
      pam_set_item(pamh, PAM_AUTHTOK_TYPE, *argv + 5);
    } else if (!strncmp(*argv, "authtok_type", 12)) {
      /* NOOP: for pam_get_authtok */;
    } else if (!strncmp(*argv, "use_authtok", 11)) {
      /* NOOP: for pam_get_authtok */;
    } else if (!strncmp(*argv, "use_first_pass", 14)) {
      /* NOOP: for pam_get_authtok */;
    } else if (!strncmp(*argv, "try_first_pass", 14)) {
      /* NOOP: for pam_get_authtok */;
    } else {
      pam_syslog(pamh, LOG_ERR,
        "pam_zxcvbn: unknown or broken option; %s", *argv);
    }
  }

  if (entropy_and_score == 3)
    debug_log(pamh, opt, LOG_WARN, "min_entropy and min_score both set. min_score will be ignored.");
}

static void debug_log(pam_handle_t *pamh, struct module_options *opt, int level, char *fmt, ...) {
  if (!opt->debug) return;

  va_list args;
  va_start(args, fmt);

  pam_vsyslog(pamh, level, fmt, args);

  va_end(args);
}
