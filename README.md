# tofurkey - a tool for distributed sync of TCP Fastopen key rotations

This is a simple daemon which manages the timely, synchronized,
deterministic rotation of TCP Fastopen (TFO) keys across a cluster of
Linux machines.  Keys are set via the Linux 5.10+ procfs interface for
dual keys in `/proc/sys/net/ipv4/tcp_fastopen_key` .  It requires as
input a long-term main secret key file which is shared across the
cluster (by you and/or your configuration/secret management system).

This main secret is used to key a KDF function (blake2b from libsodium),
which in turn is used with a time-based counter to rotate ephemeral TFO
keys supplied to the kernel.  Old keys are honored for a while after
generating a new primary key, and upcoming keys are honored for a while
before they become the new primary key, and therefore the time
transitions should be smooth for clients which are reconnecting
regularly and/or crossing between cluster machines with loose time sync.
So long as NTP is keeping your servers at least roughly in sync, and
they all independently run "tofurkey" with the same interval argument
and main secret key contents, your TFO clients should remain happy.

All operations of this daemon are idempotent given identical system
times, main keys, and arguments.  I use the term "daemon" loosely here -
it runs persistently, but in the foreground without any true
daemonization magic (e.g. fork/setsid/etc), assuming that systemd or
some other daemon management system will manage its execution.  You stop
it with fatal signals such as SIGTERM.

## Usage

    tofurkey [-vVno] [-T n] [-P /proc/sys/net/ipv4/tcp_fastopen_key] [-i seconds] -k /path/to/main/secret
    -k -- REQUIRED - Path to long-term main secret file
          (must have exactly 32 bytes of secret binary data.  Will be re-read every time keys are generated!)
    -i -- Interval seconds for key rotation, default is 21600 (6 hours), allowed range is 10 - 604800, must be even
          (daemon wakes up to rotate keys at every half-interval of unix time to manage validity overlaps)
    -v -- Verbose output to stderr
    -n -- Dry-run mode - Data is not actually written to procfs, but everything else still happens
    -o -- One-shot mode - it will calculate the current keys and set them once and then exit.
          (normal mode is to remain running and rotate keys on timer intervals forever)
    -V -- Verbose and also print TFO keys (mostly for testing, this leaks short-term secrets to stderr!)
    -P -- Override default procfs output path for setting keys (mostly for testing)
    -T -- Set a fake unix time value which never changes (mostly for testing, min value 1000000)

## Operational details about timing

The generated keys will only match across the cluster if both the main
secret **and** the interval are identical on all servers.  A new primary
ephemeral key comes into use every interval seconds.  The daemon wakes
up and makes new writes to procfs every half-interval to support properly
overlapping validity periods.

The Linux procfs interface takes two keys as input.  The first is the
current primary key used to generate new client cookies, and the second
is a backup key whose cookies are also honored from TFO clients.

Given "Tn" denotes the configured key interval periods, this is basically
how the timeline of key rotations plays out, waking up to do something
roughly 2.02 seconds (to allow some timer slop and ensure we're on the correct
side of time comparisons) after each half-interval boundary in the unix wall
clock time (i.e. roughly unix time % half-interval == 2):

* T0:
  * generate keys for T0 (current primary) and T-1 (what would have been the previous primary)
  * Write [T0, T-1] to procfs (T0 is current for new cookies, T-1 is honored for valid previous cookies)
* T0.5:
  * generate keys for T0 (current primary) and T1 (next upcoming primary)
  * Write [T0, T1] to procfs (T0 is still current, T1 is honored for validity, in case another cluster member starts using it before us)
* T1:
  * generate keys for T1 (current primary) and T0 (previous primary)
  * Write [T1, T0] to procfs (T1 is now current, T0 is honored for validity)
* T1.5:
  * generate keys for T1 (current) and T2 (next)
  * Write [T1, T2]
* T2:
  * generate keys for T2 (current) and T1 (prev)
  * Write [T2, T1]
* T2.5:
  * generate keys for T2 (current) and T3 (next)
  * Write [T2, T3]
* T3:
  * generate keys for T3 (current) and T2 (prev)
  * Write [T3, T2]
* [and so-on ...]

Clients will pick up cookies with roughly one full interval of validity
on the underlying key, on average, and it will always be in the range of
0.5-1.5 intervals of validity. For the default 6h interval, the range
would be ~3-9 hours of validity.

## Building

This is a very simple project, there's just one C file, basically. Everything
about the build assumes a modern Linux environment and tooling (gcc, gnu make,
glibc, etc). As library dependencies, you'll also need to install developer
versions (headers included!) of libev4 and libsodium (1.0.12 or higher).

Build with: `make`

Run basic tests with: `make check`

Install with: `sudo make install bindir=/usr/bin` -- Note this installs just one binary, defaults to /usr/local/bin/ . Can override via variables `prefix`, `exec_prefix`, and/or `bindir`

Run slower tests with `make check SLOW_TESTS=1`

Run code quality checks with: `make qa` -- Note this requires several tools (valgrind, cppcheck, clang analyzer, astyle) and may only work with the local versions of these that I happen to use!  It's mostly for use during my development.

There's also a trivial example systemd unit file in the source tree as `tofurkey.service`
