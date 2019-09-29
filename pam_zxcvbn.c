#include <string.h>
#include <math.h>
#include <unistd.h>
#include <syslog.h>
#include <zxcvbn/zxcvbn.h>

// TODO: translate
/* #include <libintl.h>
#define _(str) gettext (str) */

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

struct module_options {
  int tries;
  int enforce_for_root;
  int min_score;
  double min_entropy;
  /* maybe later */
  // int local_users_only;
};

static void debug_log(pam_handle_t *pamh, int flag, int level, char *fmt, ...);
static int parse_arguments(pam_handle_t *pamh, struct module_options *opt, int argc, const char **argv);
static int zxcvbn_score(double entropy);

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  /* As long as we’re linked, everything should be fine */
  int init_status = ZxcvbnInit();
  struct module_options options;
  int retval, debug;
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
    debug = parse_arguments(pamh, &options, argc, argv);
    debug_log(pamh, debug, LOG_NOTICE, "UNKNOWN flags setting %02X", flags);
    return PAM_SERVICE_ERR;
  }

  options.tries = MIN_TRIES;
  options.min_score = MIN_SCORE;
  options.min_entropy = MIN_ENTROPY;

  debug = parse_arguments(pamh, &options, argc, argv);

  retval = pam_get_user(pamh, &user, NULL);

  if (retval != PAM_SUCCESS || user == NULL) {
    debug_log(pamh, debug, LOG_ERR, "Cannot get username");
    return PAM_AUTHTOK_ERR;
  }

  // TODO: Maybe add this to the user dict later?
  // retval = pam_get_item(pamh, PAM_OLDAUTHTOK, &oldtoken);
  // if (retval != PAM_SUCCESS) {
  //   debug_log(pamh, debug, LOG_ERR, "Can not get old passwd")
  //   oldtoken = NULL;
  // }

  for(tries = 0 ; tries < options.tries ; tries++) {
    const char *new_token = NULL;
    // TODO: Use matches
    // ZxcMatch_t *matches;
    double entropy;

    retval = pam_get_authtok_noverify(pamh, &new_token, NULL);

    if (retval != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "pam_get_authtok_noverify returned error: %s", pam_strerror(pamh, retval));
      continue;
    } else if (new_token == NULL) { /* user aborted password change */
      return PAM_AUTHTOK_ERR;
    }

    // TODO: Add a user dictionary
    // TODO: Use matches
    // entropy = ZxcvbnMatch(new_token, NULL, &matches);
    entropy = ZxcvbnMatch(new_token, NULL, NULL);
    debug_log(pamh, debug, LOG_INFO, "ZxcvbnMatch returned: %lf", entropy);

    int bad_password = 0;

    if (options.min_entropy > 0) {
      if (entropy < options.min_entropy) {
        bad_password = 1;
        debug_log(pamh, debug, LOG_INFO, "Bad password: inssufficient entropy: %lf < %lf", entropy,
                  options.min_entropy);
        pam_error(pamh, "BAD PASSWORD: inssufficient entropy: %lf < %lf. Try adding some words", entropy,
                  options.min_entropy);
      }
    } else {
      int score = zxcvbn_score(entropy);
      debug_log(pamh, debug, LOG_DEBUG, "Password Score: %d", score);
      if (score < options.min_score) {
        bad_password = 1;
        debug_log(pamh, debug, LOG_INFO, "Bad password: score %d < %d", score, options.min_score);
        pam_error(pamh, "BAD PASSWORD: score %d < %d. Try adding some words", score, options.min_score);
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
      pam_syslog(pamh, LOG_ERR, "pam_get_authtok_verify returned error: %s", pam_strerror(pamh, retval));
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

static int parse_arguments(pam_handle_t *pamh, struct module_options *opt, int argc, const char **argv) {
  int debug = 0;

  int entropy_and_score = 0;

  for (debug = 0; argc-- > 0; ++argv) {
    char *end = NULL;

    if (!strcmp(*argv, "debug")){
      debug |= DEBUG_FLAG;
    } else if (!strncmp(*argv, "type=", 5)) {
      pam_set_item (pamh, PAM_AUTHTOK_TYPE, *argv+5);
    } else if (!strncmp(*argv, "retry=", 6)) {
      opt->tries = strtol(*argv+6, &end, 10);
      if (!end || (opt->tries < MIN_TRIES)) {
        debug_log(pamh, debug, LOG_WARN, "Invalid retry value: %s", *argv+6);
        opt->tries = MIN_TRIES;
      }
      end = NULL;
    } else if (!strncmp(*argv, "min_entropy=", 12)) {
      opt->min_entropy = strtod(*argv+12, &end);
      if(!end || (opt->min_entropy < 0.0L)) {
        debug_log(pamh, debug, LOG_WARN, "Invalid min_entropy value: %s", *argv+12);
        opt->min_entropy = MIN_ENTROPY;
      } else {
        entropy_and_score |= 1;
      }
      end = NULL;
    } else if (!strncmp(*argv, "min_score=", 10)) {
      opt->min_score = strtod(*argv+10, &end);
      if(!end || (opt->min_score <= 0)) {
        debug_log(pamh, debug, LOG_WARN, "Invalid min_score value: %s", *argv+10);
        opt->min_score = MIN_ENTROPY;
      } else {
        entropy_and_score |= 2;
      }
      end = NULL;
    } else if (!strncmp(*argv, "enforce_for_root", 16)) {
      opt->enforce_for_root = 1;
    } else if (!strncmp(*argv, "local_users_only", 16)) {
      // TODO
      /* opt->local_users_only = 1; */
      debug_log(pamh, debug, LOG_WARN, "WARNING: local_users_only is not currently implemented.")
    } else if (!strncmp(*argv, "authtok_type", 12)) {
      /* TODO: Support this in prompts */;
    } else if (!strncmp(*argv, "use_authtok", 11)) {
      /* for pam_get_authtok, ignore */;
    } else if (!strncmp(*argv, "use_first_pass", 14)) {
      /* for pam_get_authtok, ignore */;
    } else if (!strncmp(*argv, "try_first_pass", 14)) {
      /* for pam_get_authtok, ignore */;
    } else {
      pam_syslog(pamh, LOG_ERR,
        "pam_zxcvbn: unknown or broken option; %s", *argv);
    }
  }

  if (entropy_and_score == 3)
    debug_log(pamh, debug, LOG_WARN, "min_entropy and min_score both set. min_score will be ignored.");

   return debug;
}

static void debug_log(pam_handle_t *pamh, int flag, int level, char *fmt, ...) {
  if (!flag) return;

  va_list args;
  va_start(args, fmt);

  pam_syslog(pamh, level, fmt, args);

  va_end(args);
}
