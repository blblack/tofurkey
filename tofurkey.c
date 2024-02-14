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

#define log_info(fmt_, ...) do {\
    fprintf(stderr, fmt_ "\n", ##__VA_ARGS__);\
} while(0)

#define log_verbose(fmt_, ...) do {\
    if (cfg_p->verbose)\
        fprintf(stderr, fmt_ "\n", ##__VA_ARGS__);\
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
// clock_gettime(CLOCK_REALTIME) and also from our -T fake testing time.
// It's important that it can't go negative, doesn't get anywhere near
// saturating int64_t, and that the min is larger than MIN_IVAL above.
#define MIN_REAL_TIME 1000000      // ~ Jan 12, 1970
#define MAX_REAL_TIME 100000000000 // ~ Nov 16, 5138

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
    char* main_key_path;
    char* procfs_path;
    char* autokey_path;
    int64_t fake_time;
    int64_t interval;
    int64_t half_interval; // derived from above for convenience
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

// Safely read the main key file. If anything goes amiss, main_key will be
// wiped (if we even attempted a read) and the error will be logged to stderr.
// false -> success, true -> error
F_NONNULL
static bool safe_read_keyfile(uint8_t main_key[static restrict crypto_kdf_blake2b_KEYBYTES],
                              const char* restrict main_key_path)
{
    const size_t klen = crypto_kdf_blake2b_KEYBYTES; // for brevity below

    const int key_fd = open(main_key_path, O_CLOEXEC | O_RDONLY);
    if (key_fd < 0) {
        log_info("open(%s) failed: %s", main_key_path, strerror(errno));
        return true;
    }

    bool rv = false;
    const ssize_t readrv = read(key_fd, main_key, klen);
    if (readrv != (ssize_t)klen) {
        sodium_memzero(main_key, klen);
        if (readrv < 0)
            log_info("read(%s, %zu) failed: %s", main_key_path, klen, strerror(errno));
        else
            log_info("read(%s): wanted %zu bytes, got %zi bytes", main_key_path, klen, readrv);
        rv = true;
    }
    if (close(key_fd)) {
        sodium_memzero(main_key, klen);
        log_info("close(%s) failed: %s", main_key_path, strerror(errno));
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

    const int procfs_fd = open(procfs_path, O_CLOEXEC | O_WRONLY);
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
static void safe_write_autokey(uint8_t main_key[static restrict crypto_kdf_blake2b_KEYBYTES],
                               const char* restrict autokey_path)
{
    const size_t klen = crypto_kdf_blake2b_KEYBYTES; // for brevity below

    const int autokey_fd = open(autokey_path,
                                O_CLOEXEC | O_WRONLY | O_CREAT | O_TRUNC | O_SYNC,
                                S_IRUSR | S_IWUSR);
    if (autokey_fd < 0) {
        sodium_memzero(main_key, klen);
        log_fatal("open(%s) failed: %s", autokey_path, strerror(errno));
    }
    const ssize_t writerv = write(autokey_fd, main_key, klen);
    if (writerv != (ssize_t)klen) {
        sodium_memzero(main_key, klen);
        if (writerv < 0)
            log_fatal("write(%s, %zu) failed: %s", autokey_path, klen, strerror(errno));
        else
            log_fatal("write(%s): wanted %zu bytes, got %zi bytes", autokey_path, klen, writerv);
    }
    if (close(autokey_fd)) {
        sodium_memzero(main_key, klen);
        log_fatal("close(%s) failed: %s", autokey_path, strerror(errno));
    }
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

// CLOCK_REALTIME, ignoring nanoseconds, range-validated, converted to i64
F_NONNULL
static int64_t realtime_i64(const struct cfg* cfg_p)
{
    if (cfg_p->fake_time)
        return cfg_p->fake_time;
    struct timespec ts = { 0 };
    if (clock_gettime(CLOCK_REALTIME, &ts))
        log_fatal("clock_gettime(CLOCK_REALTIME) failed: %s", strerror(errno));
    const int64_t secs = (int64_t)ts.tv_sec;
    if (secs < MIN_REAL_TIME || secs > MAX_REAL_TIME)
        log_fatal("Bad wall clock unix time %" PRIi64, secs);
    return secs;
}

// The inner, security-sensitive part of set_keys()
F_NONNULL
static void set_keys_secure(const struct cfg* cfg_p, const int64_t now,
                            const int64_t ctr_primary, const int64_t ctr_backup)
{
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
    if (safe_read_keyfile(k->main, cfg_p->main_key_path))
        log_fatal("Could not read key file %s", cfg_p->main_key_path);

    // generate the pair of timed keys to set
    crypto_kdf_blake2b_derive_from_key(k->primary, sizeof(k->primary),
                                       (uint64_t)ctr_primary, kdf_ctx, k->main);
    crypto_kdf_blake2b_derive_from_key(k->backup, sizeof(k->primary),
                                       (uint64_t)ctr_backup, kdf_ctx, k->main);

    // Wipe keys as we stop needing them from here down:
    sodium_memzero(k->main, sizeof(k->main));
    convert_keys_ascii(k->ascii, k->primary, k->backup);
    sodium_memzero(k->primary, sizeof(k->primary));
    sodium_memzero(k->backup, sizeof(k->backup));
    if (cfg_p->verbose_leaky)
        log_verbose("Generated ASCII TFO keys for procfs write: "
                    "[%" PRIi64 "] %s", now, k->ascii);
    if (!cfg_p->dry_run)
        safe_write_procfs(k->ascii, cfg_p->procfs_path);
    sodium_memzero(k->ascii, sizeof(k->ascii)); // redundant, for clarity/consistency
    sodium_free(k);
    restore_signals(&saved_sigs);
    if (cfg_p->dry_run)
        log_verbose("Did not write to procfs because dry-run (-n) was specified");
}

// Do the idempotent key generation + deployment based on current wall clock
// (even if it's not exactly when we would've woken up), then returns the next
// time we should wake up to rotate
F_NONNULL
static int64_t set_keys(const struct cfg* cfg_p)
{
    const int64_t now = realtime_i64(cfg_p);
    log_info("Setting keys for unix time %" PRIi64, now);

    // "ctr_primary" is a counter number for how many whole intervals have
    // passed since unix time zero, and relies on the sanity checks here:
    assert(cfg_p->interval >= MIN_IVAL); // enforced at cfg parse time
    assert(now > cfg_p->interval); // current time is sane, should be way past interval
    const int64_t ctr_primary = now / cfg_p->interval;
    assert(ctr_primary > 0);

    // Detect whether "now" lands in the second (or first) half of the current
    // interval period, for switching how we manage the current "backup" key
    // written to procfs for smooth rollovers.

    // "now_rounded_down" is the unix time exactly at the start of the current interval
    const int64_t now_rounded_down = ctr_primary * cfg_p->interval;

    // assert no overflow on the multiply above, and that the relationship is sane:
    assert(now_rounded_down / cfg_p->interval == ctr_primary);
    assert(now >= now_rounded_down);

    // Which half is determined by the time that has passed since now_rounded_down
    const int64_t leftover = now - now_rounded_down;
    assert(leftover < cfg_p->interval);
    const bool second_half = (leftover >= cfg_p->half_interval);

    // If we're past the middle of the interval, define "backup" as the next
    // upcoming key else define "backup" as the previous key (primary is always current):
    const int64_t ctr_backup = second_half ? ctr_primary + 1 : ctr_primary - 1;

    // Do the security-sensitive parts (loading, generating, writing keys)
    set_keys_secure(cfg_p, now, ctr_primary, ctr_backup);

    // return the next time value we should aim to wake up at, which is the
    // next round half-interval
    const int64_t to_add = second_half ? cfg_p->interval : cfg_p->half_interval;
    const int64_t next_wake = now_rounded_down + to_add;
    return next_wake;
}

F_NONNULL
static void autokey_setup(struct cfg* cfg_p)
{
    assert(cfg_p->autokey_path); // parse_args has run
    assert(!cfg_p->main_key_path); // no -k was given

    log_info("No -k argument was given, so this invocation will use a local, "
             "autogenerated key at '%s'. This will /not/ allow for "
             "synchronization across hosts!", cfg_p->autokey_path);

    // First, copy the autokey_path to the main key path, to make it trivial
    // for all other functions:
    cfg_p->main_key_path = strdup(cfg_p->autokey_path);

    sigset_t saved_sigs;
    block_all_signals(&saved_sigs);

    // Allocate temporary main key storage
    uint8_t* main_key = sodium_malloc(crypto_kdf_blake2b_KEYBYTES);
    if (!main_key)
        log_fatal("sodium_malloc() failed: %s", strerror(errno));

    // Do a trial read to determine if there's an existing autokey file which
    // is usable. If it's not usable, invent a random key and persist it.
    if (safe_read_keyfile(main_key, cfg_p->main_key_path)) {
        log_info("Could not read autokey file %s, generating a new random one",
                 cfg_p->main_key_path);
        randombytes_buf(main_key, crypto_kdf_blake2b_KEYBYTES);
        safe_write_autokey(main_key, cfg_p->autokey_path);
    }
    sodium_free(main_key);

    restore_signals(&saved_sigs);
}

F_NONNULL
static void sysd_notify_ready(const char* spath)
{
    /* Must be an abstract socket, or an absolute path */
    if ((spath[0] != '@' && spath[0] != '/') || spath[1] == 0)
        log_fatal("Invalid NOTIFY_SOCKET path '%s'", spath);

    struct sockaddr_un sun = { 0 };
    sun.sun_family = AF_UNIX;
    const size_t plen = strlen(spath) + 1U;
    if (plen > sizeof(sun.sun_path))
        log_fatal("Implementation bug/limit: desired control socket path %s "
                  "exceeds sun_path length of %zu", spath, sizeof(sun.sun_path));
    memcpy(sun.sun_path, spath, plen);
    const socklen_t sun_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + plen);

    if (sun.sun_path[0] == '@')
        sun.sun_path[0] = 0;

    char msg[64];
    const int snp_rv = snprintf(msg, 64, "MAINPID=%lu\nREADY=1", (unsigned long)getpid());
    if (snp_rv < 0 || snp_rv >= 64)
        log_fatal("BUG: snprintf()=>%i in sysd_notify_ready()", snp_rv);

    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        log_fatal("Cannot create AF_UNIX socket");

    struct iovec iov = { .iov_base = msg, .iov_len = strlen(msg) };
    const struct msghdr m = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_name = &sun,
        .msg_namelen = sun_len
    };

    const ssize_t sm_rv = sendmsg(fd, &m, MSG_NOSIGNAL);
    if (sm_rv < 0)
        log_fatal("sendmsg() to systemd NOTIFY_SOCKET failed: %s", strerror(errno));

    if (close(fd))
        log_fatal("close() of systemd NOTIFY_SOCKET failed: %s", strerror(errno));
}

static void usage(void)
{
    fprintf(stderr,
            "tofurkey [-vno] [-i seconds] [-a %s] [-k /path/to/main/secret]\n"
            "-k -- Path to long-term main secret file generated and distributed to a\n"
            "      cluster by the administrator. This file must exist and have at least\n"
            "      32 bytes of secret high-entropy binary data, and will be re-read every\n"
            "      time TFO keys are generated. Mutually exclusive with -a. If this option\n"
            "      is not provided, then the -a autokey mode is the default.\n"
            "-a -- Custom pathname to persist an auto-generated key, defaults to\n"
            "      '%s'. This file will be created if it's missing\n"
            "      and persisted across runs, but perhaps not across reboots at the\n"
            "      default path, and obviously affords no possibility of distributed\n"
            "      sync across a cluster. Mutually exclusive with -k.\n"
            "-i -- Interval seconds for key rotation, default is %s, allowed range\n"
            "      is %s - %s, must be even. Daemon wakes up to rotate keys at\n"
            "      every half-interval of unix time to manage validity overlaps.\n"
            "      Intervals *must* match across a cluster to get the same keys!\n"
            "-v -- Verbose output to stderr\n"
            "-n -- Dry-run mode - Data is not actually written to procfs, but everything\n"
            "      else still happens\n"
            "-o -- One-shot mode - it will calculate the current keys and set them once\n"
            "      and then exit. Normal mode is to remain running and rotate keys on\n"
            "      timer intervals forever.\n"
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
    // Basic defaults:
    cfg_p->procfs_path = strdup(def_procfs_path);
    cfg_p->autokey_path = strdup(def_autokey_path);
    cfg_p->interval = DEF_IVAL;
    cfg_p->half_interval = cfg_p->interval >> 1U;

    bool a_set = false;
    int optchar;
    long long llval;
    while ((optchar = getopt(argc, argv, "k:i:P:T:a:vVno"))) {
        switch (optchar) {
        case 'k':
            if (cfg_p->main_key_path)
                free(cfg_p->main_key_path);
            cfg_p->main_key_path = strdup(optarg);
            break;
        case 'P':
            free(cfg_p->procfs_path);
            cfg_p->procfs_path = strdup(optarg);
            break;
        case 'a':
            free(cfg_p->autokey_path);
            cfg_p->autokey_path = strdup(optarg);
            a_set = true;
            break;
        case 'i':
            errno = 0;
            llval = strtoll(optarg, NULL, 10);
            if (errno || llval < MIN_IVAL || llval > MAX_IVAL || llval & 1)
                usage();
            cfg_p->interval = (int64_t)llval;
            cfg_p->half_interval = cfg_p->interval >> 1U;
            break;
        case 'T':
            errno = 0;
            llval = strtoll(optarg, NULL, 10);
            if (errno || llval < MIN_REAL_TIME || llval > MAX_REAL_TIME)
                usage();
            cfg_p->fake_time = (int64_t)llval;
            cfg_p->one_shot = true;
            break;
        case 'v':
            cfg_p->verbose = true;
            break;
        case 'V':
            cfg_p->verbose = true;
            cfg_p->verbose_leaky = true;
            break;
        case 'n':
            cfg_p->dry_run = true;
            break;
        case 'o':
            cfg_p->one_shot = true;
            break;
        case -1:
            if (optind != argc)
                usage();
            return;
        default:
            usage();
        }
    }

    if (a_set && cfg_p->main_key_path)
        usage();
}

F_NONNULL
static void cfg_cleanup(struct cfg* cfg_p)
{
    free(cfg_p->main_key_path);
    free(cfg_p->autokey_path);
    free(cfg_p->procfs_path);
}

int main(int argc, char* argv[])
{
    if (sodium_init() < 0)
        log_fatal("Could not initialize libsodium!");

    struct cfg cfg = { 0 };
    struct cfg* cfg_p = &cfg; // ptr for consistency in log_foo() macros
    parse_args(argc, argv, cfg_p);

    // If -k is not given, attempt to setup and persist an automagic key at the
    // path from -a (default default is /run/tofurkey.autokey), and fail if we
    // can't write it.
    if (!cfg_p->main_key_path)
        autokey_setup(cfg_p);

    // Initially set keys to whatever the current wall clock dictates, and exit
    // immediately if one-shot mode
    int64_t next_wake = set_keys(cfg_p);
    if (!cfg.one_shot) {
        // For the long-running case, notify systemd of readiness after the initial
        // setting of keys above, iff NOTIFY_SOCKET was set in the environment by
        // systemd. This allows systemd-level dependencies to work (if a network
        // daemon binds to tofurkey.service, it can be assured the keys have been
        // set before it starts).
        const char* spath = getenv("NOTIFY_SOCKET");
        if (spath)
            sysd_notify_ready(spath);

        // We hang out in this time loop until something kills us
        log_verbose("Will set keys at each half-interval, when unix_time %%"
                    " %" PRIi64 " ~= 2", cfg_p->half_interval);
        while (1) {
            const struct timespec next_ts = { .tv_sec = next_wake + FUDGE_S, .tv_nsec = FUDGE_NS };
            log_verbose("Sleeping until next half-interval wakeup at %" PRIi64,
                        (int64_t)next_ts.tv_sec);
            const int cnrv = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &next_ts, NULL);
            if (cnrv && errno != EINTR)
                log_fatal("clock_nanosleep() failed: %s", strerror(errno));
            next_wake = set_keys(cfg_p);
        }
    } else {
        log_info("Exiting due to one-shot mode (-o flag)");
    }
    cfg_cleanup(cfg_p);
    return 0;
}
