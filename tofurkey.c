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

// Min/max real wall clock time we'll accept as legitimate and sane from
// clock_gettime(CLOCK_REALTIME) and also from our -T fake testing time.
// It's important that it can't go negative, doesn't get anywhere near
// saturating int64_t, and that the min is larger than the min interval.
#define MIN_REAL_TIME 1000000      // ~ Jan 12, 1970
#define MAX_REAL_TIME 100000000000 // ~ Nov 16, 5138

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

// Safely write the keys to procfs, internally fatal after clearing/freeing the
// secure storage
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

// Safely write an autogenerated main key, internally fatal after
// clearing the secure storage
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

// Do the idempotent key generation + deployment based on current wall clock
// (even if it's not exactly when we would've woken up), then returns the next
// time we should wake up to rotate
F_NONNULL
static int64_t do_keys(const struct cfg* cfg_p)
{
    const int64_t now = realtime_i64(cfg_p);
    log_info("Setting keys for unix time %" PRIi64, now);

    // "ctr_primary" is a counter number for how many whole intervals have
    // passed since unix time zero, and relies on the sanity checks here:
    assert(cfg_p->interval >= 10); // enforced at cfg parse time
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

    // Block all signals until we're done with security-sensitive memory
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if (sigprocmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("sigprocmask() failed: %s", strerror(errno));

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

    // primary key is always the one for the current interval:
    crypto_kdf_blake2b_derive_from_key(k->primary, sizeof(k->primary),
                                       (uint64_t)ctr_primary, kdf_ctx, k->main);
    // If we're past the middle of the interval, define "backup" as the next upcoming key
    // else define "backup" as the previous key:
    const int64_t ctr_backup = second_half ? ctr_primary + 1 : ctr_primary - 1;
    crypto_kdf_blake2b_derive_from_key(k->backup, sizeof(k->primary),
                                       (uint64_t)ctr_backup, kdf_ctx, k->main);

    // Wipe keys as we stop needing them from here down:
    sodium_memzero(k->main, sizeof(k->main));
    convert_keys_ascii(k->ascii, k->primary, k->backup);
    sodium_memzero(k->primary, sizeof(k->primary));
    sodium_memzero(k->backup, sizeof(k->backup));
    if (cfg_p->verbose_leaky) {
        const char* half = second_half ? "2nd" : "1st";
        log_verbose("... Generated ASCII TFO keys for procfs write: "
                    "[%" PRIi64 "] (%s half) %s", now, half, k->ascii);
    }
    if (!cfg_p->dry_run)
        safe_write_procfs(k->ascii, cfg_p->procfs_path);
    sodium_memzero(k->ascii, sizeof(k->ascii)); // redundant, for clarity/consistency
    sodium_free(k);

    // Restore normal signal handling
    if (sigprocmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("sigprocmask() failed: %s", strerror(errno));

    if (cfg_p->dry_run)
        log_verbose("... did not write to procfs because dry-run (-n) was specified");
    if (!cfg_p->one_shot)
        log_verbose("... done, waiting for next half-interval wakeup");

    // return the next time value we should aim to wake up at,
    // which is ~2s past the next round half-interval
    int64_t next_wake = now_rounded_down + 2 + cfg_p->half_interval;
    if (second_half)
        next_wake += cfg_p->half_interval;
    return next_wake;
}

F_NONNULL
static void autokey_setup(struct cfg* cfg_p)
{
    assert(cfg_p->autokey_path); // parse_args has run
    assert(!cfg_p->main_key_path); // no -k was given

    log_info("No -k argument was given, so this invocation will use a local, "
             "autogenerated key at '%s'.  This will /not/ allow for "
             "synchronization across hosts!", cfg_p->autokey_path);

    // First, copy the autokey_path to the main key path, to make it trivial
    // for all other functions:
    cfg_p->main_key_path = strdup(cfg_p->autokey_path);

    // Block all signals until we're done with security-sensitive memory
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if (sigprocmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("sigprocmask() failed: %s", strerror(errno));

    // Allocate temporary main key storage
    uint8_t* main_key = sodium_malloc(crypto_kdf_blake2b_KEYBYTES);
    if (!main_key)
        log_fatal("sodium_malloc() failed: %s", strerror(errno));

    // Do a trial read to determine if there's an existing autokey file which
    // is usable.  If it's not usable, invent a random key and persist it.
    if (safe_read_keyfile(main_key, cfg_p->main_key_path)) {
        log_info("Could not read autokey file %s, generating a new random one",
                 cfg_p->main_key_path);
        randombytes_buf(main_key, crypto_kdf_blake2b_KEYBYTES);
        safe_write_autokey(main_key, cfg_p->autokey_path);
    }
    sodium_free(main_key);

    // Restore normal signal handling
    if (sigprocmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("sigprocmask() failed: %s", strerror(errno));
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
    int snp_rv = snprintf(msg, 64, "MAINPID=%lu\nREADY=1", (unsigned long)getpid());
    if (snp_rv < 0 || snp_rv >= 64)
        log_fatal("BUG: snprintf()=>%i in sysd_notify_ready()", snp_rv);

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        log_fatal("Cannot create AF_UNIX socket");

    struct iovec iov = { .iov_base = msg, .iov_len = strlen(msg) };
    struct msghdr m = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_name = &sun,
        .msg_namelen = sun_len
    };

    ssize_t sm_rv = sendmsg(fd, &m, MSG_NOSIGNAL);
    if (sm_rv < 0)
        log_fatal("sendmsg() to systemd NOTIFY_SOCKET failed: %s", strerror(errno));

    if (close(fd))
        log_fatal("close() of systemd NOTIFY_SOCKET failed: %s", strerror(errno));
}

static void usage(void)
{
    fprintf(stderr,
            "tofurkey [-vVno] [-T n] [-P %s]\n"
            "         [-i seconds] [-a %s] [-k /path/to/main/secret]\n"
            "-k -- Path to long-term main secret file. This file must have at least 32\n"
            "      bytes of secret binary data, and will be re-read every time runtime\n"
            "      TFO keys are generated. Without this option, the daemon will attempt\n"
            "      to persist an automatic key to the rundir on startup, but this\n"
            "      affords no possibility of distributed sync across a cluster, and may\n"
            "      be regenerated after e.g. reboots as well.\n"
            "-a -- Filename to persist an auto-generated key, if -k is not used.\n"
            "      Defaults to %s\n"
            "-i -- Interval seconds for key rotation, default is 21600 (6 hours),\n"
            "      allowed range is 10 - 604800, must be even (daemon wakes up to rotate\n"
            "      keys at every half-interval of unix time to manage validity overlaps)\n"
            "-v -- Verbose output to stderr\n"
            "-n -- Dry-run mode - Data is not actually written to procfs, but everything\n"
            "      else still happens\n"
            "-o -- One-shot mode - it will calculate the current keys and set them once\n"
            "      and then exit. (normal mode is to remain running and rotate keys on\n"
            "      timer intervals forever)\n"
            "-V -- Verbose and also print TFO keys (mostly for testing, this leaks\n"
            "      short-term secrets to stderr!)\n"
            "-P -- Override default procfs output path for setting keys (mostly for\n"
            "      testing)\n"
            "-T -- Set a fake unix time value which never changes (mostly for testing,\n"
            "      min value " STR(MIN_REAL_TIME) ")\n\n"
            "This is tofurkey v1.0.2\n"
            "tofurkey is a tool for distributed sync of TCP Fastopen key rotations\n"
            "More info is available at https://github.com/blblack/tofurkey\n",
            def_procfs_path, def_autokey_path, def_autokey_path
           );
    exit(2);
}

F_NONNULL
static void parse_args(const int argc, char** argv, struct cfg* cfg_p)
{
    // Basic defaults:
    cfg_p->procfs_path = strdup(def_procfs_path);
    cfg_p->autokey_path = strdup(def_autokey_path);
    cfg_p->interval = 21600;
    cfg_p->half_interval = cfg_p->interval >> 1U;

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
            break;
        case 'i':
            errno = 0;
            llval = strtoll(optarg, NULL, 10);
            if (errno || llval < 10 || llval > 604800 || llval & 1)
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
}

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
    int64_t next_wake = do_keys(cfg_p);
    if (!cfg.one_shot) {
        // For the long-running case, notify systemd of readiness after the initial
        // setting of keys above, iff NOTIFY_SOCKET was set in the environment by
        // systemd.  This allows systemd-level dependencies to work (if a network
        // daemon binds to tofurkey.service, it can be assured the keys have been
        // set before it starts).
        const char* spath = getenv("NOTIFY_SOCKET");
        if (spath)
            sysd_notify_ready(spath);

        // We hang out in this time loop until something kills us
        log_verbose("Will set keys at each half-interval, when unix_time %%"
                    " %" PRIi64 " ~= 2", cfg_p->half_interval);
        while (1) {
            // The extra 20ms in tv_nsec is just insurance against boundary
            // conditions that might otherwise cause the log-reported whole seconds
            // number to not be the expected "% half-interval + 2" values.
            const struct timespec next_ts = { .tv_sec = next_wake, .tv_nsec = 20000000 };
            const int cnrv = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &next_ts, NULL);
            if (cnrv && errno != EINTR)
                log_fatal("clock_nanosleep() failed: %s", strerror(errno));
            next_wake = do_keys(cfg_p);
        }
    } else {
        log_info("Exiting due to one-shot mode (-o flag)");
    }
    cfg_cleanup(cfg_p);
    return 0;
}
