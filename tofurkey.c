// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

// Note this is not high-performance software and doesn't need to be.  Please
// use "normal" compile flags, and do **not** eliminate asserts via -DNDEBUG

#if __STDC_VERSION__ < 201112L // C11
#  error This software requires a C11 (or higher) compiler
#endif

#ifndef __linux__
#  error This software only works on modern Linux
#endif

#define _GNU_SOURCE

// system-level includes
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <sodium.h>

// Defines RUNDIR macro from rundir=x Makefile argument
#include "rundir.inc"

#define F_NONNULL __attribute__((__nonnull__))

// log outputs of various kinds:

#define log_fatal(fmt_, ...) do {\
    fprintf(stderr, "FATAL: " fmt_ "\n", ##__VA_ARGS__);\
    abort();\
} while(0)

#define usage_err(fmt_, ...) do {\
    fprintf(stderr, "error: " fmt_ "\n", ##__VA_ARGS__);\
    usage();\
} while(0)

#define log_info(fmt_, ...) do {\
    fprintf(stderr, "info: " fmt_ "\n", ##__VA_ARGS__);\
} while(0)

#define log_verbose(fmt_, ...) do {\
    if (cfg_p->verbose)\
        fprintf(stderr, "info: " fmt_ "\n", ##__VA_ARGS__);\
} while(0)

// The data length of a single ephemeral TFO key in binary form
#define TFO_KEY_LEN 16U

// The allocation length of the ASCII procfs form for 2x keys plus NUL:
// pppppppp-pppppppp-pppppppp-pppppppp,bbbbbbbb-bbbbbbbb-bbbbbbbb-bbbbbbbb\0
// 64 bytes of hex digits plus 6x dashes, 1x comma, and 1x NUL = 72
#define TFO_ASCII_ALLOC 72U

// These timer "fudge" values are used to add an extra ~2.02s to the wake time
// for some insurance against various inaccuracies. Waking up slightly-late is
// fine, but waking up slight-early is not!
#define FUDGE_S 2
#define FUDGE_NS (20 * 1000 * 1000) // 20ms

// Min/def/max user-specified interval values.  While the upper bound is fairly
// arbitrary, the lower bound really should not go any lower than ~10s!  Given
// that the interval is cut in half for timers and there's a fixed 2.02s
// offset, this means with the min of 10, we'll be firing every 5 seconds with
// only ~3 seconds of room (after the offset) before the next firing.  The time
// math also asserts on this minimum for functional reasons!
#define MIN_IVAL 10
#define DEF_IVAL 86400
#define MAX_IVAL 604800

// Min/max real wall clock time we'll accept as legitimate and sane from
// clock_gettime(CLOCK_REALTIME) and also from our -T fake testing time. It's
// important that it can't go negative, that the min is larger than MAX_IVAL
// above, and that our time values (after adding an interval and fudge factor)
// can't saturate an i64)
#define MIN_REAL_TIME 1000000      // ~ Jan 12, 1970
#define MAX_REAL_TIME 100000000000 // ~ Nov 16, 5138
_Static_assert(MIN_REAL_TIME > MAX_IVAL);
_Static_assert(MAX_REAL_TIME + MAX_IVAL + FUDGE_S < INT64_MAX);
// Assert that time_t (type of .tv_sec) can hold the same positive range as
// int64_t. This code is intentionally not compatible with 32-bit time_t!
_Static_assert(sizeof(time_t) >= sizeof(int64_t));

// Default pathnames:
static const char def_autokey_path[] = RUNDIR "/tofurkey.autokey";
static const char def_procfs_path[] = "/proc/sys/net/ipv4/tcp_fastopen_key";

// Constant non-secret context for the KDF (like an app-specific fixed salt)
static const char kdf_ctx[crypto_kdf_blake2b_CONTEXTBYTES] = {
    't', 'o', 'f', 'u', 'r', 'k', 'e', 'y'
};

// Assert that kdf_blake2b has the sizes we expect
_Static_assert(crypto_kdf_blake2b_CONTEXTBYTES == 8U, "b2b has 8 ctx bytes");
_Static_assert(crypto_kdf_blake2b_KEYBYTES == 32U, "b2b has 32 key bytes");
_Static_assert(TFO_KEY_LEN >= crypto_kdf_blake2b_BYTES_MIN, "TFO_KEY_LEN >= b2b min");
_Static_assert(TFO_KEY_LEN <= crypto_kdf_blake2b_BYTES_MAX, "TFO_KEY_LEN <= b2b max");

// Stringify magic
#define STR_(x) #x
#define STR(x) STR_(x)

// Structure carrying fixed configuration from CLI down to functional parts
struct cfg {
    char* mainkey_path;
    char* procfs_path;
    uint64_t fake_time;
    uint64_t interval;
    bool verbose;
    bool verbose_leaky;
    bool dry_run;
    bool one_shot;
};

// Helpers to block/restore signals around sensitive code paths
F_NONNULL
static void block_all_signals(sigset_t* saved_sigs)
{
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigemptyset(saved_sigs);
    if (sigprocmask(SIG_SETMASK, &sigmask_all, saved_sigs))
        log_fatal("sigprocmask() failed: %s", strerror(errno));
}

F_NONNULL
static void restore_signals(const sigset_t* saved_sigs)
{
    if (sigprocmask(SIG_SETMASK, saved_sigs, NULL))
        log_fatal("sigprocmask() failed: %s", strerror(errno));
}

// Notify systemd iff NOTIFY_SOCKET was set in the environment. This allows
// systemd-level dependencies to work: if a network daemon binds/wants
// tofurkey, it can be assured the keys have been initially set.
static void sysd_notify_ready(void)
{
    const char* spath = getenv("NOTIFY_SOCKET");
    if (!spath)
        return;

    // Must be an abstract socket or absolute path
    if ((spath[0] != '@' && spath[0] != '/') || spath[1] == 0)
        log_fatal("Invalid systemd NOTIFY_SOCKET path '%s'", spath);

    struct sockaddr_un sun = { .sun_family = AF_UNIX };
    const size_t plen = strlen(spath) + 1U;
    if (plen > sizeof(sun.sun_path))
        log_fatal("systemd NOTIFY_SOCKET path '%s' exceeds sun_path length of %zu",
                  spath, sizeof(sun.sun_path));
    memcpy(sun.sun_path, spath, plen);
    const socklen_t sun_len = (socklen_t)sizeof(struct sockaddr_un);
    if (sun.sun_path[0] == '@')
        sun.sun_path[0] = 0;

    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        log_fatal("Cannot create unix dgram socket fd for systemd NOTIFY_SOCKET");
    const ssize_t strv = sendto(fd, "READY=1", 7U, MSG_NOSIGNAL, &sun, sun_len);
    if (strv < 0)
        log_fatal("Cannot send READY=1 to systemd NOTIFY_SOCKET '%s': %s", spath, strerror(errno));
    if (strv != 7)
        log_fatal("Cannot send READY=1 to systemd NOTIFY_SOCKET '%s' (sent %zi/7 bytes)", spath, strv);
    if (close(fd))
        log_fatal("close() of systemd NOTIFY_SOCKET '%s' failed: %s", spath, strerror(errno));
}

// Safely read the main key file. If anything goes amiss, mainkey will be
// wiped (if we even attempted a read) and the error will be logged to stderr.
// false -> success, true -> error
F_NONNULL
static bool safe_read_key(uint8_t mainkey[static restrict crypto_kdf_blake2b_KEYBYTES],
                          const char* restrict mainkey_path)
{
    const size_t klen = crypto_kdf_blake2b_KEYBYTES; // for brevity below

    const int key_fd = open(mainkey_path, O_CLOEXEC | O_RDONLY);
    if (key_fd < 0) {
        log_info("open(%s) failed: %s", mainkey_path, strerror(errno));
        return true;
    }

    bool rv = false;
    const ssize_t readrv = read(key_fd, mainkey, klen);
    if (readrv != (ssize_t)klen) {
        sodium_memzero(mainkey, klen);
        if (readrv < 0)
            log_info("read(%s, %zu) failed: %s", mainkey_path, klen, strerror(errno));
        else
            log_info("read(%s): wanted %zu bytes, got %zi bytes", mainkey_path, klen, readrv);
        rv = true;
    }
    if (close(key_fd)) {
        sodium_memzero(mainkey, klen);
        log_info("close(%s) failed: %s", mainkey_path, strerror(errno));
        rv = true;
    }
    return rv;
}

// Safely write the keys to procfs, internally fatal after clearing storage
F_NONNULL
static void safe_write_procfs(char keys_ascii[static restrict TFO_ASCII_ALLOC],
                              const char* restrict procfs_path)
{
    const size_t klen = TFO_ASCII_ALLOC; // for brevity below

    const int procfs_fd = open(procfs_path, O_CLOEXEC | O_WRONLY | O_SYNC);
    if (procfs_fd < 0) {
        sodium_memzero(keys_ascii, klen);
        log_fatal("open(%s) failed: %s", procfs_path, strerror(errno));
    }
    const ssize_t writerv = write(procfs_fd, keys_ascii, klen);
    if (writerv != (ssize_t)klen) {
        sodium_memzero(keys_ascii, klen);
        if (writerv < 0)
            log_fatal("write(%s, %zu) failed: %s", procfs_path, klen, strerror(errno));
        else
            log_fatal("write(%s): wanted %zu bytes, got %zi bytes", procfs_path, klen, writerv);
    }
    if (close(procfs_fd)) {
        sodium_memzero(keys_ascii, klen);
        log_fatal("close(%s) failed: %s", procfs_path, strerror(errno));
    }
}

// Safely write an autogenerated main key, internally fatal after clearing storage
F_NONNULL
static void safe_write_autokey(uint8_t mainkey[static restrict crypto_kdf_blake2b_KEYBYTES],
                               const char* restrict autokey_path)
{
    const size_t klen = crypto_kdf_blake2b_KEYBYTES; // for brevity below

    const int autokey_fd = open(autokey_path,
                                O_CLOEXEC | O_WRONLY | O_CREAT | O_TRUNC | O_SYNC,
                                S_IRUSR | S_IWUSR);
    if (autokey_fd < 0) {
        sodium_memzero(mainkey, klen);
        log_fatal("open(%s) failed: %s", autokey_path, strerror(errno));
    }
    const ssize_t writerv = write(autokey_fd, mainkey, klen);
    if (writerv != (ssize_t)klen) {
        sodium_memzero(mainkey, klen);
        if (writerv < 0)
            log_fatal("write(%s, %zu) failed: %s", autokey_path, klen, strerror(errno));
        else
            log_fatal("write(%s): wanted %zu bytes, got %zi bytes", autokey_path, klen, writerv);
    }
    if (close(autokey_fd)) {
        sodium_memzero(mainkey, klen);
        log_fatal("close(%s) failed: %s", autokey_path, strerror(errno));
    }
}

F_NONNULL
static void autokey_setup(const char* mainkey_path)
{
    log_info("No -k argument was given, so this invocation will use a local, "
             "autogenerated key at '%s'. This will /not/ allow for "
             "synchronization across hosts!", mainkey_path);

    // Block signals while dealing with secure memory so that we always wipe
    // before exiting on a clean terminating signal
    sigset_t saved_sigs;
    block_all_signals(&saved_sigs);

    // Allocate temporary main key storage
    uint8_t* mainkey = sodium_malloc(crypto_kdf_blake2b_KEYBYTES);
    if (!mainkey)
        log_fatal("sodium_malloc() failed: %s", strerror(errno));
    // Do a trial read to determine if there's an existing autokey file which
    // is usable. If it's not usable, invent a random key and persist it.
    if (safe_read_key(mainkey, mainkey_path)) {
        log_info("Could not read autokey file %s, generating a new random one",
                 mainkey_path);
        randombytes_buf(mainkey, crypto_kdf_blake2b_KEYBYTES);
        safe_write_autokey(mainkey, mainkey_path);
    }
    sodium_free(mainkey);
    restore_signals(&saved_sigs);
}

// Convert a pair of 16 byte raw binary keys to the ASCII hexadecimal format
// preferred by the Linux procfs interface
F_NONNULL
static void convert_keys_ascii(char keys_ascii[static restrict TFO_ASCII_ALLOC],
                               const uint8_t kp[static restrict TFO_KEY_LEN],
                               const uint8_t kb[static restrict TFO_KEY_LEN])
{
#define H8_ "%02hhx%02hhx%02hhx%02hhx"
#define HK_ H8_ "-" H8_ "-" H8_ "-" H8_
    const int snp_rv = snprintf(keys_ascii, TFO_ASCII_ALLOC, HK_ "," HK_,
                                kp[0],  kp[1],  kp[2],  kp[3],  kp[4],  kp[5],  kp[6],  kp[7],
                                kp[8],  kp[9],  kp[10], kp[11], kp[12], kp[13], kp[14], kp[15],
                                kb[0],  kb[1],  kb[2],  kb[3],  kb[4],  kb[5],  kb[6],  kb[7],
                                kb[8],  kb[9],  kb[10], kb[11], kb[12], kb[13], kb[14], kb[15]
                               );
    assert(snp_rv == (TFO_ASCII_ALLOC - 1U));
#undef HK_
#undef H8_
}

// CLOCK_REALTIME, ignoring nanoseconds, range-validated, converted to u64, and
// overridden by config if necc
static uint64_t realtime_u64(const uint64_t fake_time)
{
    if (fake_time)
        return fake_time;
    struct timespec ts = { 0 };
    if (clock_gettime(CLOCK_REALTIME, &ts))
        log_fatal("clock_gettime(CLOCK_REALTIME) failed: %s", strerror(errno));
    if (ts.tv_sec < MIN_REAL_TIME || ts.tv_sec > MAX_REAL_TIME)
        log_fatal("Bad wall clock unix time %" PRIi64, (int64_t)ts.tv_sec);
    return (uint64_t)ts.tv_sec;
}

// timecalc() is a pure numeric function that takes care of the critical
// time-based calculations that are performed to create time-relevant keys.
// All inputs and outputs are uint64_t.  It takes in "now" (current unix wall
// time in seconds) and the configured interval, and outputs the two counter
// values for primary and backup TFO key derivation as well as the wall time we
// should next wake after in order to set keys again.

struct tc_out {
    uint64_t ctr_primary;
    uint64_t ctr_backup;
    uint64_t next_wake;
};

static struct tc_out timecalc(uint64_t now, uint64_t interval)
{
    // "ctr_primary" is a counter number for how many whole intervals have
    // passed since unix time zero, and relies on the sanity checks here:
    assert(interval >= MIN_IVAL); // enforced in parse_args
    assert(now > interval); // enforced indirectly (args/gettime range limits + comptime assert on range relations)
    const uint64_t ctr_primary = now / interval;
    assert(ctr_primary > 0); // implicit, but maybe not compiler-obvious

    // "now_rounded_down" is the unix time exactly at the start of the current interval
    const uint64_t now_rounded_down = ctr_primary * interval; // incapable of overflow, see above
    assert(now >= now_rounded_down); // implicit, but maybe not compiler-obvious

    // Which half is determined by the time that has passed since now_rounded_down
    const uint64_t leftover = now - now_rounded_down;
    assert(leftover < interval); // implicit, but maybe not compiler-obvious
    const uint64_t half_interval = interval >> 1;
    const bool second_half = (leftover >= half_interval);

    // If we're past the middle of the interval, define "backup" as the next
    // upcoming key else define "backup" as the previous key (primary is always current):
    const uint64_t ctr_backup = second_half ? ctr_primary + 1 : ctr_primary - 1;

    // next time we should wake up after, which is the next round half-interval
    const uint64_t to_add = second_half ? interval : half_interval;
    const uint64_t next_wake = now_rounded_down + to_add;
    return (struct tc_out) {
        .ctr_primary = ctr_primary,
        .ctr_backup = ctr_backup,
        .next_wake = next_wake,
    };
}

static void usage(void)
{
    fprintf(stderr,
            "\n"
            "Usage: tofurkey [-vno] [-i seconds] [-a %s] [-k /path/to/main/secret]\n"
            "  -k Path to long-term main secret file generated and distributed to a\n"
            "     cluster by the administrator. This file must exist and have at least\n"
            "     32 bytes of secret high-entropy binary data, and will be re-read every\n"
            "     time TFO keys are generated. Mutually exclusive with -a. If this option\n"
            "     is not provided, then the -a autokey mode is the default.\n"
            "  -a Custom pathname to persist an auto-generated key, defaults to\n"
            "     '%s'. This file will be created if it's missing\n"
            "     and persisted across runs, but perhaps not across reboots at the\n"
            "     default path, and obviously affords no possibility of distributed\n"
            "     sync across a cluster. Mutually exclusive with -k.\n"
            "  -i Interval seconds for key rotation, default is %s, allowed range\n"
            "     is %s - %s, must be even. Daemon wakes up to rotate keys at\n"
            "     every half-interval of unix time to manage validity overlaps.\n"
            "     Intervals *must* match across a cluster to get the same keys!\n"
            "  -v Verbose output to stderr\n"
            "  -n Dry-run mode - Data is not actually written to procfs, but everything\n"
            "     else still happens\n"
            "  -o One-shot mode - it will calculate the current keys and set them once\n"
            "     and then exit. Normal mode is to remain running and rotate keys on\n"
            "     timer intervals forever.\n"
            "\n"
            "This is tofurkey v1.1.0\n"
            "tofurkey is a tool for distributed sync of Linux TCP Fastopen key rotations\n"
            "More info is available at https://github.com/blblack/tofurkey\n",
            def_autokey_path, def_autokey_path, STR(DEF_IVAL), STR(MIN_IVAL), STR(MAX_IVAL)
           );
    exit(2);
}

F_NONNULL
static void parse_args(const int argc, char** argv, struct cfg* cfg_p)
{
    const char* arg_autokey = NULL;
    const char* arg_mainkey = NULL;
    const char* arg_procfs = NULL;
    int optchar;
    unsigned long long ullval;
    while ((optchar = getopt(argc, argv, ":k:i:P:T:a:vVno")) != -1) {
        switch (optchar) {
        case 'v':
            cfg_p->verbose = true;
            break;
        case 'n':
            cfg_p->dry_run = true;
            break;
        case 'o':
            cfg_p->one_shot = true;
            break;
        case 'k':
            arg_mainkey = optarg;
            break;
        case 'a':
            arg_autokey = optarg;
            break;
        case 'i':
            errno = 0;
            ullval = strtoull(optarg, NULL, 10);
            if (errno || ullval < MIN_IVAL || ullval > MAX_IVAL || ullval & 1)
                usage_err("Interval value '%s' unparseable, out of range, or odd", optarg);
            cfg_p->interval = (uint64_t)ullval;
            break;
        // These three are just for testsuite/debugging:
        case 'P':
            arg_procfs = optarg;
            break;
        case 'V':
            cfg_p->verbose = true;
            cfg_p->verbose_leaky = true;
            break;
        case 'T':
            errno = 0;
            ullval = strtoull(optarg, NULL, 10);
            if (errno || ullval < MIN_REAL_TIME || ullval > MAX_REAL_TIME)
                usage_err("Faketime value '%s' unparseable or out of range", optarg);
            cfg_p->fake_time = (uint64_t)ullval;
            cfg_p->one_shot = true;
            break;
        // Error cases:
        case '?':
            usage_err("Invalid Option '-%c'", (char)optopt);
            break;
        case ':':
            usage_err("Missing argument for '-%c'", (char)optopt);
            break;
        default:
            usage_err("Unknown error processing CLI options");
            break;
        }
    }

    if (optind != argc)
        usage_err("Excess unknown CLI arguments after options");

    if (!cfg_p->interval)
        cfg_p->interval = DEF_IVAL;

    if (arg_procfs)
        cfg_p->procfs_path = strdup(arg_procfs);
    else
        cfg_p->procfs_path = strdup(def_procfs_path);

    if (arg_mainkey) {
        if (arg_autokey)
            usage_err("Cannot set both -k and -a");
        cfg_p->mainkey_path = strdup(arg_mainkey);
    } else {
        if (arg_autokey)
            cfg_p->mainkey_path = strdup(arg_autokey);
        else
            cfg_p->mainkey_path = strdup(def_autokey_path);
        autokey_setup(cfg_p->mainkey_path);
    }
}

F_NONNULL
static void cfg_cleanup(struct cfg* cfg_p)
{
    free(cfg_p->mainkey_path);
    free(cfg_p->procfs_path);
}

// The inner, security-sensitive part of set_keys()
F_NONNULL
static void set_keys_secure(const struct cfg* cfg_p, const uint64_t now,
                            const uint64_t ctr_primary, const uint64_t ctr_backup)
{
    // Block signals while dealing with secure memory so that we always wipe
    // before exiting on a clean terminating signal
    sigset_t saved_sigs;
    block_all_signals(&saved_sigs);

    // Allocate secure storage for all key materials
    struct keys {
        uint8_t main[crypto_kdf_blake2b_KEYBYTES];
        uint8_t primary[TFO_KEY_LEN];
        uint8_t backup[TFO_KEY_LEN];
        char ascii[TFO_ASCII_ALLOC];
    };
    struct keys* k = sodium_malloc(sizeof(*k));
    if (!k)
        log_fatal("sodium_malloc() failed: %s", strerror(errno));

    // Now read in the long-term main key file and generate our pair of ephemeral keys:
    if (safe_read_key(k->main, cfg_p->mainkey_path))
        log_fatal("Could not read key file %s", cfg_p->mainkey_path);

    // generate the pair of timed keys to set
    if (crypto_kdf_blake2b_derive_from_key(k->primary, sizeof(k->primary),
                                           ctr_primary, kdf_ctx, k->main)) {
        sodium_memzero(k, sizeof(*k));
        log_fatal("b2b_derive_from_key failed");
    }
    if (crypto_kdf_blake2b_derive_from_key(k->backup, sizeof(k->primary),
                                           ctr_backup, kdf_ctx, k->main)) {
        sodium_memzero(k, sizeof(*k));
        log_fatal("b2b_derive_from_key failed");
    }
    sodium_memzero(k->main, sizeof(k->main));

    // convert the pair to the procfs ASCII format
    convert_keys_ascii(k->ascii, k->primary, k->backup);
    sodium_memzero(k->primary, sizeof(k->primary));
    sodium_memzero(k->backup, sizeof(k->backup));

    if (cfg_p->verbose_leaky)
        log_verbose("Generated ASCII TFO keys for procfs write: "
                    "[%" PRIu64 "] %s", now, k->ascii);
    if (!cfg_p->dry_run)
        safe_write_procfs(k->ascii, cfg_p->procfs_path);
    sodium_memzero(k->ascii, sizeof(k->ascii)); // redundant, for clarity/consistency
    sodium_free(k);
    restore_signals(&saved_sigs);
}

// Do the idempotent key generation + deployment based on current wall clock
// (even if it's not exactly when we would've woken up), then returns the next
// time we should wake up to rotate
F_NONNULL
static uint64_t set_keys(const struct cfg* cfg_p)
{
    const uint64_t now = realtime_u64(cfg_p->fake_time);
    log_info("Setting keys for unix time %" PRIu64, now);
    struct tc_out tc = timecalc(now, cfg_p->interval);
    set_keys_secure(cfg_p, now, tc.ctr_primary, tc.ctr_backup);
    if (cfg_p->dry_run)
        log_verbose("Did not write to procfs because dry-run (-n) was specified");
    return tc.next_wake;
}

int main(int argc, char* argv[])
{
    if (sodium_init() < 0)
        log_fatal("Could not initialize libsodium!");

    struct cfg cfg = { 0 };
    struct cfg* cfg_p = &cfg; // ptr for consistency in log_foo() macros
    parse_args(argc, argv, cfg_p);

    // Initially set keys to whatever the current wall clock dictates, and exit
    // immediately if one-shot mode
    uint64_t next_wake = set_keys(cfg_p);
    if (!cfg.one_shot) {
        // For the long-running case, notify systemd of readiness after the initial
        // setting of keys above.
        sysd_notify_ready();

        // We hang out in this time loop until something kills us
        log_verbose("Will set keys at each half-interval, when unix_time %%"
                    " %" PRIu64 " ~= 2", cfg_p->interval >> 1);
        while (1) {
            const uint64_t next_fudged = next_wake + FUDGE_S;
            const struct timespec next_ts = { .tv_sec = (time_t)next_fudged, .tv_nsec = FUDGE_NS };
            log_verbose("Sleeping until next half-interval wakeup at %" PRIu64, next_fudged);
            const int cnrv = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &next_ts, NULL);
            if (cnrv)
                log_fatal("clock_nanosleep() failed: %s", strerror(cnrv));
            next_wake = set_keys(cfg_p);
        }
    } else {
        log_info("Exiting due to one-shot mode (-o flag)");
    }
    cfg_cleanup(cfg_p);
    return 0;
}
