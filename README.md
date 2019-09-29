# pam_zxcvbn

A PAM module for password strength estimation using [zxcvbn-c](https://github.com/tsyrogit/zxcvbn-c). It can be
plugged in to enforce password entropy, requiring a minimum for the average number of guesses an attacker would need to
make to brute-force the password. This module only implements the `password` stack. It is meant as a replacement for
pam_pwquality or pam_cracklib.

The library uses pattern matching and conservative estimation, to recognize and weigh 30,000 common passwords, common
names and surnames according to US census data, popular English words from Wikipedia and US television and movies, and
other common patterns like dates, repeats (aaa), sequences (abcd), keyboard patterns (qwertyuiop), and l33t speak
alternatives for all of the above.

The sequence of actions are as follows:

1. Prompt the user for a new password (or pull it from `use_first_pass` or `try_first_pass`, if set and this is the
   first time prompting)
1. Test the password for strength based on defaults or configured limits. On failure, return to step 1.
1. Prompt the user to verify their password
1. If the passwords do not match, return to step 1.
1. Pass the new password on for use in modules stacked below this one in the `password` stack.

## Usage

In the simplest case, this module provides reasonable defaults and requires no arguments:

```pam
password	required	pam_zxcvbn.so
```

A more common usage might look something like this:

```pam
password	required	pam_zxcvbn.so try_first_pass retry=3 authtok_type=
```

### Available Options

<dl>
  <dt><code><strong>debug</strong></code></dt>
  <dd>
    Enable debugging information to syslog. Does not log passwords, but provides helpful information about what the
    module is doing. Specifying this option first will allow debugging of following options.
  </dd>
  <dt><code><strong>retry=</strong>&lt;N&gt;</code></dt>
  <dd>Prompt user at most N times before returning with error. The default is 1.</dd>
  <dt><code><strong>min_score=</strong>&lt;N&gt;</code></dt>
  <dd>
    Minimum <a href="https://github.com/dropbox/zxcvbn">zxcvbn</a> score for the password:
    <ol start="0">
      <li>Too guessable: risky password. (guesses < 10<sup>3</sup>)</li>
      <li>Very guessable: protection from throttled online attacks. (guesses < 10<sup>6</sup>)</li>
      <li>Somewhat guessable: protection from unthrottled online attacks. (guesses < 10<sup>8</sup>)</li>
      <li>Safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10<sup>10</sup>)</li>
      <li>Very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10<sup>10</sup>)</li>
    </ol>
    The default is 3.
    <p>
      <strong>NOTE:</strong> if both <code>min_score</code> and <code>min_entropy</code> are specified, only
      <code>min_entropy</code> will be used.
    </p>
  </dd>
  <dt><code><strong>min_entropy=</strong>&lt;F.FF&gt;</code></dt>
  <dd>
    Minimum entropy for the password for finer grained control, expressed as the log<sub>10</sub>(guesses).<br>
    <p>
      <strong>NOTE:</strong> if both <code>min_score</code> and <code>min_entropy</code> are specified, only
      <code>min_entropy</code> will be used.
    </p>
  </dd>
  <dt><code><strong>enforce_for_root</strong></code></dt>
  <dd>
    By default when root is setting a password the <code>min_score</code> and <code>min_entropy</code> failures are
    treated as warnings. This option turns them back into errors.
  </dd>
  <dt><code><strong>local_users_only</strong></code></dt>
  <dd>
    Users must be in the local password file to have their passwords tested. Users will still be prompted for their
    password, so that modules later in the stack can use it with <code>use_authtok</code> option. This option is
    disabled by default.
  </dd>
  <dt><code><strong>local_users_file=</strong>&lt;FILE&gt;</code></dt>
  <dd>
    The passwd-style file used to search for local users if <code>local_users_only</code> is enabled. Defaults to
    <code>/etc/passwd</code>.
  </dd>
  <dt><code><strong>authtok_type=</strong>&lt;TYPE&gt;</code></dt>
  <dd>
    The default action is for the module to use the following prompts when requesting passwords: <code>New UNIX
    password: </code> and <code>Retype UNIX password: </code>. The example word UNIX can be replaced with this option,
    by default it is empty.
  </dd>
  <dt><code><strong>try_first_pass</strong></code></dt>
  <dd>Before prompting the user for their password, first try a previous stacked module’s password.</dd>
  <dt><code><strong>use_first_pass</strong></code></dt>
  <dd>
    Force the use of a previous stacked module’s password. If no password is available or the password is not
    appropriate, the user will be denied access.
  </dd>
  <dt><code><strong>use_authtok</strong></code></dt>
  <dd>
    When changing a user password, force the module to set the new token to the one provided by a previously stacked
    password module. If no token is available token changing will fail.
  </dd>
</dl>

## References

Original CoffeeScript library implementation: [zxcvbn](https://github.com/dropbox/zxcvbn).

C library port: [zxcvbn-c](https://github.com/tsyrogit/zxcvbn-c)

## License

&copy; 2019 Erik Ogan &amp; Stealthy Monkeys Consulting, released under the
[MIT License](https://spdx.org/licenses/MIT).
