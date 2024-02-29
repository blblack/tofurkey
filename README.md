# tofurkey - a tool for distributed sync of Linux TCP Fastopen key rotations

This is a simple daemon which manages the timely, synchronized,
deterministic rotation of TCP Fastopen (TFO) keys across a cluster of
Linux machines. Keys are set via the Linux 5.10+ procfs interface for
dual keys in `/proc/sys/net/ipv4/tcp_fastopen_key` .

In order to synchronize across a cluster, it requires as input a
long-term main secret key file which is shared across the cluster (by
you and/or your configuration/secret management system), set via the
`-k` argument, which points at a secret file with at least 32 bytes of
high-entropy random data to use as a main key.

If `-k` is not supplied, a random secret will be auto-generated and
persisted to the (reboot-volatile) rundir by default, which will allow
for local TFO key rotation without any synchronization or reboot
persistence. A warning will be issued to stderr at startup in this
case, as it's not expected to be a common operating mode in production.

The main secret is used as input to a key derivation function (blake2b
from libsodium), which in turn is used with a time-based counter to
rotate ephemeral TFO keys supplied to the kernel. Old keys are honored
for a while after generating a new primary key, and upcoming keys are
honored for a while before they become the new primary key, and
therefore the time transitions should be smooth for clients which are
reconnecting regularly and/or crossing between cluster machines with
loose time sync. So long as NTP is keeping your servers at least roughly
in sync, and they all independently run "tofurkey" with the same
interval argument and main secret key contents, your TFO clients should
remain happy.

All operations of this daemon are idempotent given identical system
times, main keys, and arguments. I use the term "daemon" loosely here -
it runs persistently, but in the foreground without any true
daemonization magic (e.g. fork/setsid/etc), assuming that systemd or
some other daemon management system will manage its execution. You stop
it with fatal signals such as SIGTERM.

## Usage

    Usage: tofurkey [-vno] [-i seconds] [-a /run/tofurkey.autokey] [-k /path/to/main/secret]
      -k Path to long-term main secret file generated and distributed to a
         cluster by the administrator. This file must exist and have at least
         32 bytes of secret high-entropy binary data, and will be re-read every
         time TFO keys are generated. Mutually exclusive with -a. If this option
         is not provided, then the -a autokey mode is the default.
      -a Custom pathname to persist an auto-generated key, defaults to
         '/run/tofurkey.autokey'. This file will be created if it's missing
         and persisted across runs, but perhaps not across reboots at the
         default path, and obviously affords no possibility of distributed
         sync across a cluster. Mutually exclusive with -k.
      -i Interval seconds for key rotation, default is 86400, allowed range
         is 10 - 604800, must be even. Daemon wakes up to rotate keys at
         every half-interval of unix time to manage validity overlaps.
         Intervals *must* match across a cluster to get the same keys!
      -v Verbose output to stderr
      -n Dry-run mode - Data is not actually written to procfs, but everything
         else still happens
      -o One-shot mode - it will calculate the current keys and set them once
         and then exit. Normal mode is to remain running and rotate keys on
         timer intervals forever.

## Generating and managing the main key

The main, long-term, secret key file which is given as the argument to
`-k` must contain at least 32 bytes of high-entropy secret key material
generated securely. Exactly 32 bytes will be read from it. It is up to
you how you securely generate and distribute such a key across your
cluster. One trivial way to create a decent one is:

    dd if=/dev/random of=/path/to/main.key bs=32 count=1

Note that the key is re-read from disk on every half-interval wakeup.
Because of this, it is possible to replace your main key with a new one
once in a blue moon with only a minimal disruption in TFO validity for
clients. Ideally you'd replace the key roughly simultaneously on all
servers, and either do so at a time that is not close to a half-interval
boundary, or restart the daemons shortly afterwards to be sure one
doesn't remain out of sync due to timing boundary issues. You can
observe the half-interval timing from the stderr output of the daemon,
and it should be happening when `unix_time modulo (interval/2) == 2`.

## Operational details about timing

The generated TFO keys will only match across the cluster and across
time if both the main secret **and** the interval are identical on all
servers. A new primary ephemeral key comes into use every interval
seconds. The daemon wakes up and makes new writes to procfs every
half-interval to support properly overlapping validity periods. The
daemon also writes keys once at startup immediately, using the keys that
would have most-recently been set at the previous half-interval
boundary.

The Linux procfs interface takes two keys as input. The first is the
current primary key used to generate new client cookies, and the second
is a backup key whose cookies are also honored from TFO clients.

Given "Tn" denotes the configured key interval periods, and "Kn" denotes
the primary key whose official lifetime starts at Tn, this is basically
how the timeline of key rotations plays out, waking up to do something
roughly 2.02 seconds (to allow some timer slop and ensure we're on the
correct side of time comparisons) after each half-interval boundary in
the unix wall clock time:

* T0:
  * generate keys for K0 (current primary) and K-1 (what would have been the previous primary)
  * Write [K0, K-1] to procfs (K0 is current for new cookies, K-1 is honored for valid previous cookies)
* T0.5:
  * generate keys for K0 (current primary) and K1 (next upcoming primary)
  * Write [K0, K1] to procfs (K0 is still current, K1 is honored for validity, in case another cluster member starts using it before us)
* T1:
  * generate keys for K1 (current primary) and K0 (previous primary)
  * Write [K1, K0] to procfs (K1 is now current, K0 is honored for validity)
* T1.5:
  * Generate and write [K1 (current), K2 (next)]
* T2:
  * Generate and write [K2 (current), K1 (prev)]
* T2.5:
  * Generate and write [K2 (current), K3 (next)]
* T3:
  * Generate and write [K3 (current), K2 (prev)]
* [and so-on ...]

Clients will pick up cookies with roughly one full interval of validity
on the underlying key, on average, and it will always be in the range of
0.5-1.5 intervals of validity. For the default 24h interval, the range
would be ~12-36 hours of validity.

## Building

This is a very simple project, there's just one C file, basically. Everything
about the build assumes a modern Linux environment and tooling (gcc, gnu make,
glibc, etc). It does have one library dependency: you'll need to install the
developer package (headers included!) of libsodium 1.0.12 or higher.

Build with: `make` (optionally: set make argument `rundir=/foo` to override the default of '/run' for the autokey storage path)

Run basic tests with: `make check`

Install with: `sudo make install`. This installs two files by default at `/usr/sbin/tofurkey` and `/usr/share/man/man8/tofurkey.8`. Can override paths via the autotools-like make variables `DESTDIR`, `prefix`, `exec_prefix`, `sbindir`, `datarootdir`, `mandir`, and/or `man8dir` with their usual relationships.

Run slower tests with `make check SLOW_TESTS=1` (requires python3, and the "nacl" python module)

Run code quality checks with: `make qa` -- Note this requires several more tools (valgrind, cppcheck, clang analyzer, astyle) and may only work with the local versions of these that I happen to use!  It's mostly for use during my development.

There's also a trivial example systemd unit file in the source tree as `tofurkey.service`

## Experimental Zig Port!

This repo now also contains an experimental port of tofurkey's C code to
zig. I made this port mostly as a learning exercise.  I won't promise
anything about the quality of the ported code, as I'm still learning the
language and the language itself is not yet stable. Consider it
EXPERIMENTAL!

This port aims to mirror the C code as closely as it reasonably can,
making comparison of the two languages easy, while still taking
advantage of Zig stuff everywhere it can.  It generally has the same
core function names, same approximate file layout, mostly the same
commentary and log outputs, etc.  I plan to keep this port in sync with
changes to the C source as I go.  As with the C code, it requires
libsodium (and headers).

Currently, this builds correctly with both zig 0.11.0 and zig's current
(as of this writing) master branch (0.12.0-dev), by the magic of
@hasDecl and @typeInfo.

### Building/testing/installing the experimental zig port

    # Run unit tests (Zig-only):
    zig build test
    # Run quick integration tests (same tests as C "make check"):
    zig build itest
    # Run slow integration tests (same tests as C "make check SLOW_TESTS=1"):
    zig build itest-slow
    # Install in-tree (installs binary and manpage into subpaths within ./zig-out/):
    zig build install

    # Notes:
    #  * All "zig build" commands can take optional arguments:
    #        -Doptimize={Debug|ReleaseSafe|ReleaseSmall|ReleaseFast}
    #        -Drundir=/run
    #  * For install step (the default), default installation prefix is
    #    ./zig-out, but you can override with e.g.:
    #        --prefix /usr
    #  * You can do more than one build command in one invocation
    #  * Results (executables, test results, etc) are cached locally and
    #    re-used by future invocations, assuming same -D args.
    #  * If you don't see an error message, assume it did the things
    #    successfully (zig tends to only generate output by default if
    #    something fails)
    #  * You can add flags "--summary all" and/or "--verbose" to see
    #    more of what's happening, including those silent successes
    #    and/or re-use of cached results.

    # All-in-one: ReleaseSafe build mode, run unit tests, run quick
    #             integration tests, and install to ./zig-out :
    zig build test itest install -Doptimize=ReleaseSafe

    # Do the final install to system dirs (reuses cached compile from above):
    sudo zig build install -Doptimize=ReleaseSafe --prefix /usr
