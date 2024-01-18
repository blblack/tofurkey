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

// libsodium + libev
#include <sodium.h>
#include <ev.h>

#define F_NONNULL __attribute__((__nonnull__))

// log outputs of various kinds:

#define log_fatal(fmt_, ...) do {\
    fprintf(stderr, "FATAL: " fmt_ "\n", ##__VA_ARGS__);\
    exit(42);\
} while(0)

#define log_verbose(fmt_, ...) do {\
    if (cfg_p->verbose)\
        fprintf(stderr, fmt_ "\n", ##__VA_ARGS__);\
} while(0)

#define log_verbose_leaky(fmt_, ...) do {\
    if (cfg_p->verbose_leaky)\
        fprintf(stderr, fmt_ "\n", ##__VA_ARGS__);\
} while(0)

// The data length of a single ephemeral TFO key in binary form
#define TFO_KEY_LEN 16U

// The allocation length of the ASCII procfs form for 2x keys plus NUL:
// pppppppp-pppppppp-pppppppp-pppppppp,bbbbbbbb-bbbbbbbb-bbbbbbbb-bbbbbbbb\0
// 64 bytes of hex digits plus 6x dashes, 1x comma, and 1x NUL = 72
#define TFO_ASCII_ALLOC 72U

// Assert that kdf_blake2b has the sizes we expect
_Static_assert(crypto_kdf_blake2b_CONTEXTBYTES == 8U, "b2b has 8 ctx bytes");
_Static_assert(crypto_kdf_blake2b_KEYBYTES == 32U, "b2b has 32 key bytes");

// Structure carrying fixed configuration from CLI down to functional parts
struct cfg {
    char* main_key_path;
    char* procfs_path;
    uint64_t fake_time;
    uint64_t interval;
    uint64_t half_interval; // derived from above for convenience
    bool verbose;
    bool verbose_leaky;
    bool dry_run;
    bool one_shot;
};

// Safely read the main key file
F_NONNULL
static void safe_read_keyfile(const char* restrict main_key_path, uint8_t keybuf[static restrict crypto_kdf_blake2b_KEYBYTES])
{
    const int key_fd = open(main_key_path, O_CLOEXEC | O_RDONLY);
    if (key_fd < 0)
        log_fatal("open(%s) failed: %s", main_key_path, strerror(errno));
    const ssize_t readrv = read(key_fd, keybuf, crypto_kdf_blake2b_KEYBYTES);
    if (readrv != crypto_kdf_blake2b_KEYBYTES) {
        sodium_free(keybuf);
        log_fatal("read(%s, %u) failed: %s", main_key_path, crypto_kdf_blake2b_KEYBYTES, strerror(errno));
    }
    if (close(key_fd)) {
        sodium_free(keybuf);
        log_fatal("close(%s) failed: %s", main_key_path, strerror(errno));
    }
}

// Safely write the keys to procfs
F_NONNULL
static void safe_write_procfs(char keys_ascii[static restrict TFO_ASCII_ALLOC], const char* restrict procfs_path)
{
    const int procfs_fd = open(procfs_path, O_CLOEXEC | O_WRONLY);
    if (procfs_fd < 0) {
        sodium_free(keys_ascii);
        log_fatal("open(%s) failed: %s", procfs_path, strerror(errno));
    }
    const ssize_t writerv = write(procfs_fd, keys_ascii, TFO_ASCII_ALLOC);
    if (writerv != TFO_ASCII_ALLOC) {
        sodium_free(keys_ascii);
        log_fatal("write(%s, %u) failed: %s", procfs_path, TFO_ASCII_ALLOC, strerror(errno));
    }
    if (close(procfs_fd)) {
        sodium_free(keys_ascii);
        log_fatal("close(%s) failed: %s", procfs_path, strerror(errno));
    }
}

// Convert a pair of 16 byte raw binary keys to the ASCII hexidecimal format
// preferred by the Linux procfs interface
F_NONNULL
static void convert_keys_ascii(char keys_ascii[static restrict TFO_ASCII_ALLOC], const uint8_t kp[static restrict TFO_KEY_LEN], const uint8_t kb[static restrict TFO_KEY_LEN])
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

static uint64_t time_u64(const struct cfg* cfg_p)
{
    if (cfg_p->fake_time)
        return cfg_p->fake_time;
    return (uint64_t)time(NULL);
}

// Do the idempotent key generation + deployment
F_NONNULL
static void do_keys(const struct cfg* cfg_p, const uint64_t now)
{
    log_verbose("Setting keys for unix time %" PRIu64, now);

    // Block all signals until we're done with security-sensitive memory
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if (sigprocmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("sigprocmask() failed: %s", strerror(errno));

    // Allocate storage for various keys in various forms:
    char* keys_ascii = sodium_malloc(TFO_ASCII_ALLOC);
    uint8_t* key_backup = sodium_malloc(TFO_KEY_LEN);
    uint8_t* key_primary = sodium_malloc(TFO_KEY_LEN);
    uint8_t* main_key = sodium_malloc(crypto_kdf_blake2b_KEYBYTES);

    if (!keys_ascii || !key_backup || !key_primary || !main_key)
        log_fatal("sodium_malloc() failed: %s", strerror(errno));

    ////////
    // Interval magic to define current primary+backup keys:
    ////////

    assert(cfg_p->interval >= 10U); // enforced at cfg parse time
    assert(now > cfg_p->interval); // current time is sane, should be way past interval

    // "ctr_current" is a counter number for how many whole intervals have passed since unix time zero
    const uint64_t ctr_current = now / cfg_p->interval;
    assert(ctr_current > 0); // ctr_current should be non-zero based on earlier asserts

    // "now_rounded_down" is the unix time exactly at the start of the current interval
    const uint64_t now_rounded_down = ctr_current * cfg_p->interval;

    // assert no overflow on the multiply above, and that the relationship is sane:
    assert(now_rounded_down / cfg_p->interval == ctr_current);
    assert(now >= now_rounded_down);

    // leftover is how many seconds have passed since the current interval
    // started.  This is critical for deciding how to rotate in the backup
    // keys below.
    const uint64_t leftover = now - now_rounded_down;
    assert(leftover < cfg_p->interval);

    // Constant non-secret context for the KDF (like an app-specific fixed salt)
    static const char kdf_ctx[crypto_kdf_blake2b_CONTEXTBYTES] = {
        't', 'o', 'f', 'u', 'r', 'k', 'e', 'y'
    };

    // Now read in the long-term main key file and generate our pair of ephemeral keys:
    safe_read_keyfile(cfg_p->main_key_path, main_key);
    // primary key is always the one for the current interval:
    crypto_kdf_blake2b_derive_from_key(key_primary, TFO_KEY_LEN, ctr_current, kdf_ctx, main_key);
    // If we're past the middle of the interval, define "backup" as the next upcoming key
    // else define "backup" as the previous key:
    if (leftover >= cfg_p->half_interval) {
        log_verbose("... Second half of interval, so the backup is next interval key");
        crypto_kdf_blake2b_derive_from_key(key_backup, TFO_KEY_LEN, ctr_current + 1U, kdf_ctx, main_key);
    } else {
        log_verbose("... First half of interval, so the backup is the previous interval key");
        crypto_kdf_blake2b_derive_from_key(key_backup, TFO_KEY_LEN, ctr_current - 1U, kdf_ctx, main_key);
    }

    // Wipe keys as we stop needing them from here down:
    sodium_free(main_key);
    convert_keys_ascii(keys_ascii, key_primary, key_backup);
    sodium_free(key_primary);
    sodium_free(key_backup);

    log_verbose_leaky("... Generated ASCII TFO keys for procfs write: %s", keys_ascii);
    if (cfg_p->dry_run) {
        log_verbose("... Not writing to procfs because dry-run was specified (-n)");
    } else {
        log_verbose("... Writing new keys to procfs");
        safe_write_procfs(keys_ascii, cfg_p->procfs_path);
    }
    sodium_free(keys_ascii);

    // Restore normal signal handling
    if (sigprocmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("sigprocmask() failed: %s", strerror(errno));
    log_verbose("... Done, waiting for next half-interval wakeup");
}

F_NONNULL
static void half_interval_cb(struct ev_loop* loop, ev_periodic* w, int revents)
{
    assert(loop);
    assert(w->data);
    assert(revents == EV_PERIODIC);
    const struct cfg* cfg_p = (const struct cfg*)w->data;
    do_keys(cfg_p, time_u64(cfg_p));
}

static void sysd_notify_ready(void)
{
    const char* spath = getenv("NOTIFY_SOCKET");
    if (!spath)
        return;

    /* Must be an abstract socket, or an absolute path */
    if ((spath[0] != '@' && spath[0] != '/') || spath[1] == 0)
        log_fatal("Invalid NOTIFY_SOCKET path '%s'", spath);

    struct sockaddr_un sun = { 0 };
    sun.sun_family = AF_UNIX;
    const size_t plen = strlen(spath) + 1U;
    if (plen > sizeof(sun.sun_path))
        log_fatal("Implementation bug/limit: desired control socket path %s exceeds sun_path length of %zu", spath, sizeof(sun.sun_path));
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

    ssize_t sm_rv = sendmsg(fd, &m, 0);
    if (sm_rv < 0)
        log_fatal("sendmsg() to systemd NOTIFY_SOCKET failed: %s", strerror(errno));

    if (close(fd))
        log_fatal("close() of systemd NOTIFY_SOCKET failed: %s", strerror(errno));
}

static void usage(void)
{
    fprintf(stderr,
            "Usage: tofurkey [-vVno] [-T n ] [-P /proc/sys/net/ipv4/tcp_fastopen_key] [-i seconds] -k /path/to/main/secret\n\n"
            "-k -- REQUIRED - Path to long-term main secret file\n"
            "      (must have exactly 32 bytes of secret binary data.  Will be re-read every time keys are generated!)\n"
            "-i -- Interval seconds for key rotation, default is 21600 (6 hours), allowed range is 10 - 604800.\n"
            "      (daemon wakes up to rotate keys at every half-interval of unix time to manage validity overlaps)\n"
            "-v -- Verbose output to stderr\n"
            "-n -- Dry-run mode - Data is not actually written to procfs, but everything else still happens\n"
            "-o -- One-shot mode - it will calculate the current keys and set them once and then exit.\n"
            "      (normal mode is to remain running and rotate keys on timer intervals forever)\n"
            "-V -- Verbose and also print TFO keys (mostly for testing, this leaks short-term secrets to stderr!)\n"
            "-P -- Override default procfs output path for setting keys (mostly for testing)\n"
            "-T -- Set a fake unix time value which never changes (mostly for testing, min value 1000000)\n\n"
            "This is tofurkey v0.2\n"
           );
    exit(2);
}

F_NONNULL
static void parse_args(const int argc, char** argv, struct cfg* cfg_p)
{
    // Basic defaults:
    cfg_p->procfs_path = strdup("/proc/sys/net/ipv4/tcp_fastopen_key");
    cfg_p->interval = 21600U; // default for optional value here
    cfg_p->half_interval = cfg_p->interval >> 1U;

    int optchar;
    unsigned long long ullval;
    while ((optchar = getopt(argc, argv, "k:i:P:T:vVno"))) {
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
        case 'i':
            errno = 0;
            ullval = strtoull(optarg, NULL, 10);
            if (errno || ullval < 10LLU || ullval > 604800LLU)
                usage();
            cfg_p->interval = (uint64_t)ullval;
            cfg_p->half_interval = cfg_p->interval >> 1U;
            break;
        case 'T':
            errno = 0;
            ullval = strtoul(optarg, NULL, 10);
            if (errno || ullval < 1000000LLU)
                usage();
            cfg_p->fake_time = (uint64_t)ullval;
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

int main(int argc, char* argv[])
{
    if (sodium_init() < 0)
        log_fatal("Could not initialize libsodium!");

    struct cfg cfg = { 0 };
    struct cfg* cfg_p = &cfg; // ptr for consistency in log_foo() macros
    parse_args(argc, argv, cfg_p);
    if (!cfg_p->main_key_path)
        usage();

    // Initially set keys to whatever the current wall clock dictates, and exit
    // immediately if one-shot mode
    do_keys(cfg_p, time_u64(cfg_p));
    if (cfg.one_shot) {
        log_verbose("Exiting due to one-shot mode (-o flag)");
        free(cfg_p->procfs_path);
        free(cfg_p->main_key_path);
        return 0;
    }

    // For the long-running case, notify systemd of readiness after the initial
    // setting of keys above, iff NOTIFY_SOCKET was set in the environment by
    // systemd.  This allows systemd-level dependencies to work (if a network
    // daemon binds to tofurkey.service, it can be assured the keys have been
    // set before it starts).
    sysd_notify_ready();

    // create default ev loop
    // (note: the libev dependency seems like overkill just to run a single
    // periodic timer, but running such a timer accurately over a long period
    // of time is actually quite tricky, so this saves a bunch of headache).
    struct ev_loop* loop = ev_default_loop(EVFLAG_AUTO);
    if (!loop)
        log_fatal("Could not initialize the default libev loop");

    // We run the periodic key update at approximately 2.02 seconds after every
    // half-interval mark, as reassurance against minor time issues where e.g.
    // poor system management of leap seconds might manage to trip up
    // ev_periodic somehow (which is intended to handle them properly it sounds
    // like, but I suspect there's still room for system-level administrative
    // mistakes).
    ev_periodic half_interval;
    ev_periodic_init(&half_interval, half_interval_cb, 2.02, (double)cfg_p->half_interval, NULL);
    half_interval.data = (void*)cfg_p;
    ev_periodic_start(loop, &half_interval);

    // We spend all our runtime hanging out here until something kills us
    log_verbose("Entering runtime loop with interval value %" PRIu64 " (will wake up to rotate keys ~2s after each time the unix timestamp is evenly divisible by %" PRIu64 ")", cfg_p->interval, cfg_p->half_interval);
    ev_run(loop, 0);

    // by design, there is no way to cleanly exit the loop other than killing
    // the daemon with a terminal signal, so the code below never actually gets
    // run, it's just here for cleanliness, completeness, and future-proofing.
    free(cfg_p->procfs_path);
    free(cfg_p->main_key_path);
    return 0;
}
