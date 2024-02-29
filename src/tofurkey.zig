// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
// Handle 0.11.0->0.12-dev switch from "os" to "posix"
const posix = if (@hasDecl(std, "posix")) std.posix else std.os;
const os = std.os;
const log = std.log;
const crypto = std.crypto;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const getopt = @import("getopt.zig"); // Our POSIXy getopt() native impl
const lsys = @import("lsys.zig"); // non-libc Linux syscall stuff

// This whole project, by its functional nature, only works on Linux
comptime {
    if (builtin.os.tag != .linux) unreachable;
}

// Handle 0.11.0 -> 0.12-dev changes in how std options are overriden:
pub const std_options = if (@hasDecl(std, "Options"))
    // 0.12-dev
    .{ .log_level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    } }
else
    // 0.11.0
    struct {
        pub const log_level = switch (builtin.mode) {
            .Debug => .debug,
            else => .info,
        };
    };

// 0.11.0 vs 0.12-dev difference in open/openat flags (u32 vs struct)
const old_open_flags: bool = @typeInfo(@TypeOf(posix.openat)).Fn.params[2].type.? == u32;

// Constants for blake2b_kdf
const KDF_KEYBYTES = 32;

// The data length of a single ephemeral TFO key in binary form
const TFO_KEY_LEN = 16;

// The allocation length of the ASCII procfs form for 2x keys:
// pppppppp-pppppppp-pppppppp-pppppppp,bbbbbbbb-bbbbbbbb-bbbbbbbb-bbbbbbbb
// 64 bytes of hex digits plus 6x dashes and one comma = 71
const TFO_ASCII_ALLOC = 71;

// These timer "fudge" values are used to add an extra ~2.02s to the wake time
// for some insurance against various inaccuracies. Waking up slightly-late is
// fine, but waking up slight-early is not!
const FUDGE_S = 2;
const FUDGE_NS = 20_000_000; // 20ms

// Min/def/max user-specified interval values. While the upper bound is fairly
// arbitrary, the lower bound really should not go any lower than ~10s!  Given
// that the interval is cut in half for timers and there's a fixed 2.02s
// offset, this means with the min of 10, we'll be firing every 5 seconds with
// only ~3 seconds of room (after the offset) before the next firing. The time
// math also asserts on this minimum for functional reasons!
const MIN_IVAL = 10;
const DEF_IVAL = 86400;
const MAX_IVAL = 604800;

// Min/max real wall clock time we'll accept as legitimate and sane from
// clock_gettime(CLOCK_REALTIME) and also from our -T fake testing time. It's
// important that it can't go negative, that the min is larger than MAX_IVAL
// above, and that our time values (after adding an interval and fudge factor)
// can't saturate an i64)
const MIN_REAL_TIME = 1_000_000; // ~ Jan 12, 1970
const MAX_REAL_TIME = 100_000_000_000; // ~ Nov 16, 5138

comptime {
    // These must hold for any future changes of the constants above, or else
    // logic/correctness needs fixing in the actual code.
    assert(MIN_IVAL >= 10);
    assert(DEF_IVAL >= MIN_IVAL);
    assert(MAX_IVAL >= DEF_IVAL);
    assert(MIN_REAL_TIME > MAX_IVAL);
    assert(MAX_REAL_TIME + MAX_IVAL + FUDGE_S < std.math.maxInt(i64));
    // Assert that time_t (timespec.tv_sec) can hold the same positive range as
    // i64. This code is intentionally not compatible with 32-bit time_t!
    assert(std.math.maxInt(posix.time_t) >= std.math.maxInt(i64));
}

// Default pathnames:
const def_autokey_path = config.rundir ++ "/tofurkey.autokey";
const def_procfs_path = "/proc/sys/net/ipv4/tcp_fastopen_key";

// non-secret context for the KDF (like an app-specific fixed salt)
const kdf_ctx = [8]u8{ 't', 'o', 'f', 'u', 'r', 'k', 'e', 'y' };

// Helpers to block/restore signals around sensitive code paths
fn block_all_signals() posix.sigset_t {
    // linux filled_sigset definition copied out of master std/os/linux.zig, so
    // we can use it on 0.11.0, can remove later.
    const sigset_len = @typeInfo(posix.sigset_t).Array.len;
    const usize_bits = @typeInfo(usize).Int.bits;
    const filled_sigset = [_]u32{(1 << (31 & (usize_bits - 1))) - 1} ++ [_]u32{0} ** (sigset_len - 1);

    var sigmask_prev: posix.sigset_t = undefined;
    posix.sigprocmask(posix.SIG.SETMASK, &filled_sigset, &sigmask_prev);
    return sigmask_prev;
}

fn restore_signals(prev: posix.sigset_t) void {
    posix.sigprocmask(posix.SIG.SETMASK, &prev, null);
}

// Notify systemd iff NOTIFY_SOCKET was set in the environment. This allows
// systemd-level dependencies to work: if a network daemon binds/wants
// tofurkey, it can be assured the keys have been initially set.
fn sysd_notify_ready() !void {
    const spath = posix.getenv("NOTIFY_SOCKET") orelse return;
    // Must be an abstract socket or absolute path
    if (spath.len < 2 or (spath[0] != '@' and spath[0] != '/') or spath[1] == 0) {
        log.err("Invalid systemd NOTIFY_SOCKET path '{s}'", .{spath});
        return error.SystemdNotify;
    }
    var sun = std.net.Address.initUnix(spath) catch |err| {
        log.err("Cannot create sockaddr struct for systemd NOTIFY_SOCKET with path '{s}'", .{spath});
        return err;
    };
    if (sun.un.path[0] == '@')
        sun.un.path[0] = 0;

    const fd = posix.socket(posix.AF.UNIX, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch |err| {
        log.err("Cannot create unix dgram socket fd for systemd NOTIFY_SOCKET", .{});
        return err;
    };
    defer posix.close(fd);
    const strv = posix.sendto(fd, "READY=1", posix.MSG.NOSIGNAL, &sun.any, sun.getOsSockLen()) catch |err| {
        log.err("Cannot send READY=1 to systemd NOTIFY_SOCKET '{s}'", .{spath});
        return err;
    };
    if (strv != 7) {
        log.err("Cannot send READY=1 to systemd NOTIFY_SOCKET '{s}' (sent {d}/7 bytes)", .{ spath, strv });
        return error.SystemdNotify;
    }
}

// Safely read the main key file.
inline fn safe_read_key(mainkey: *[KDF_KEYBYTES]u8, mainkey_path: []const u8) !void {
    const key_fd = if (old_open_flags)
        try posix.open(mainkey_path, posix.O.RDONLY | posix.O.CLOEXEC, 0)
    else
        try posix.open(mainkey_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer posix.close(key_fd);
    const readrv = try posix.read(key_fd, mainkey);
    if (readrv != mainkey.len)
        return error.KeyShortRead;
}

// Safely write the keys to procfs.
inline fn safe_write_procfs(keys_ascii: *const [TFO_ASCII_ALLOC]u8, procfs_path: []const u8) !void {
    const procfs_fd = if (old_open_flags)
        try posix.open(procfs_path, posix.O.WRONLY | posix.O.CLOEXEC | posix.O.SYNC, 0)
    else
        try posix.open(procfs_path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .SYNC = true }, 0);
    defer posix.close(procfs_fd);
    const writerv = try posix.write(procfs_fd, keys_ascii);
    if (writerv != keys_ascii.len)
        return error.KeyShortWrite;
}

// Safely write an autogenerated main key.
inline fn safe_write_autokey(mainkey: *const [KDF_KEYBYTES]u8, autokey_path: []const u8) !void {
    const autokey_fd = if (old_open_flags)
        try posix.open(autokey_path, posix.O.WRONLY | posix.O.CREAT | posix.O.TRUNC | posix.O.CLOEXEC | posix.O.SYNC, posix.S.IRUSR | posix.S.IWUSR)
    else
        try posix.open(autokey_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .SYNC = true }, posix.S.IRUSR | posix.S.IWUSR);
    defer posix.close(autokey_fd);
    const writerv = try posix.write(autokey_fd, mainkey);
    if (writerv != mainkey.len)
        return error.KeyShortWrite;
}

fn autokey_setup(mainkey_path: []const u8) !void {
    log.info("No -k argument was given, so this invocation will use a local, autogenerated key at '{s}'. This will /not/ allow for synchronization across hosts!", .{mainkey_path});

    // Block signals while dealing with secure memory so that we always
    // wipe before exiting on a clean terminating signal
    const oldmask = block_all_signals();
    defer restore_signals(oldmask);

    // Temporary main key storage
    var mainkey: [KDF_KEYBYTES]u8 = undefined;
    defer crypto.utils.secureZero(u8, &mainkey);

    // Do a trial read to determine if there's an existing autokey file which
    // is usable. If it's not usable, invent a random key and persist it.
    safe_read_key(&mainkey, mainkey_path) catch {
        crypto.utils.secureZero(u8, &mainkey);
        log.info("Could not read autokey file {s}, generating a new random one", .{mainkey_path});
        crypto.random.bytes(&mainkey);
        try safe_write_autokey(&mainkey, mainkey_path);
    };
}

// Convert a pair of 16 byte raw binary keys to the ASCII hexadecimal format
// preferred by the Linux procfs interface
fn convert_keys_ascii(keys_ascii: *[TFO_ASCII_ALLOC]u8, kp: *const [TFO_KEY_LEN]u8, kb: *const [TFO_KEY_LEN]u8) !void {
    const h8 = "{x:0>2}{x:0>2}{x:0>2}{x:0>2}";
    const hk = h8 ++ "-" ++ h8 ++ "-" ++ h8 ++ "-" ++ h8;
    const hks = hk ++ "," ++ hk;
    // zig fmt: off
    const out = try std.fmt.bufPrint(keys_ascii, hks, .{
        kp[0],  kp[1], kp[2],  kp[3],  kp[4],  kp[5],  kp[6],  kp[7],
        kp[8],  kp[9], kp[10], kp[11], kp[12], kp[13], kp[14], kp[15],
        kb[0],  kb[1], kb[2],  kb[3],  kb[4],  kb[5],  kb[6],  kb[7],
        kb[8],  kb[9], kb[10], kb[11], kb[12], kb[13], kb[14], kb[15],
    });
    // zig fmt: on
    if (out.len != TFO_ASCII_ALLOC)
        return error.KeyFormattedLen;
}

// Handle 0.11.0 -> 0.12-dev capitalization change to std.builtin.Endian... :P
fn endian_little() std.builtin.Endian {
    return if (@typeInfo(std.builtin.Endian).Enum.fields[1].name[0] == 'L')
        .Little // 0.11.0
    else
        .little; // 0.12-dev
}

// Must mirror libsodium:crypto_kdf_blake2b_derive_from_key() for compat
fn blake2b_kdf(out: *[TFO_KEY_LEN]u8, subkey: u64, key: *const [KDF_KEYBYTES]u8) void {
    var ctxpad: [16]u8 = [_]u8{0} ** 16;
    @memcpy(ctxpad[0..8], &kdf_ctx);
    var salt: [16]u8 = [_]u8{0} ** 16;
    std.mem.writeInt(u64, salt[0..8], subkey, endian_little());
    crypto.hash.blake2.Blake2b128.hash("", out, .{ .key = key, .salt = salt, .context = ctxpad });
}

// CLOCK_REALTIME, ignoring nanoseconds, range-validated, converted to u64
fn realtime_u64() !u64 {
    var ts = posix.timespec{ .tv_sec = 0, .tv_nsec = 0 };
    try posix.clock_gettime(posix.CLOCK.REALTIME, &ts);
    if (ts.tv_sec < MIN_REAL_TIME or ts.tv_sec > MAX_REAL_TIME) {
        log.err("Realtime value {d} is insane", .{ts.tv_sec});
        return error.TimeRange;
    }
    return @intCast(ts.tv_sec);
}

// timecalc() is a pure numeric function that takes care of the critical
// time-based calculations that are performed to create time-relevant keys.
// All inputs and outputs are u64s.  It takes in "now" (current unix wall time
// in seconds) and the configured interval, and outputs the two counter values
// for primary and backup TFO key derivation as well as the wall time we should
// next wake after in order to set keys again.
const tc_out = struct { ctr_primary: u64, ctr_backup: u64, next_wake: u64 };
fn timecalc(now: u64, interval: u64) tc_out {
    // "ctr_primary" is a counter number for how many whole intervals have
    // passed since unix time zero, and relies on the sanity checks here:
    assert(interval >= MIN_IVAL); // enforced in parse_args
    assert(now > interval); // enforced indirectly (args/gettime range limits + comptime assert on range relations)
    const ctr_primary = now / interval;
    assert(ctr_primary > 0); // implicit, but maybe not compiler-obvious

    // "now_rounded_down" is the unix time exactly at the start of the current interval
    const now_rounded_down = ctr_primary * interval; // incapable of overflow, see above
    assert(now >= now_rounded_down); // implicit, but maybe not compiler-obvious

    // Which half is determined by the time that has passed since now_rounded_down
    const leftover = now - now_rounded_down;
    assert(leftover < interval); // implicit, but maybe not compiler-obvious
    const half_interval = interval / 2;
    const second_half = (leftover >= half_interval);

    // If we're past the middle of the interval, define "backup" as the next
    // upcoming key else define "backup" as the previous key (primary is always current):
    const ctr_backup = if (second_half) ctr_primary + 1 else ctr_primary - 1;

    // next time we should wake up after, which is the next round half-interval
    const to_add = if (second_half) interval else half_interval;
    const next_wake = now_rounded_down + to_add;

    return tc_out{
        .ctr_primary = ctr_primary,
        .ctr_backup = ctr_backup,
        .next_wake = next_wake,
    };
}

test "timecalc math checks" {
    try std.testing.expectEqualDeep(tc_out{ // A realistic example at MIN_IVAL
        .ctr_primary = 170901095,
        .ctr_backup = 170901094,
        .next_wake = 1709010955,
    }, timecalc(1709010952, 10));
    try std.testing.expectEqualDeep(tc_out{ // Maxing out time and ival
        .ctr_primary = 165343,
        .ctr_backup = 165344,
        .next_wake = 100_000_051_200, // realtime_u64() will bail
    }, timecalc(100_000_000_000, 604800));
    try std.testing.expectEqualDeep(tc_out{ // Max time, min ival
        .ctr_primary = 10_000_000_000,
        .ctr_backup = 9_999_999_999,
        .next_wake = 100_000_000_005, // realtime_u64() will bail
    }, timecalc(100_000_000_000, 10));
}

// Structure carrying fixed configuration from CLI down to functional parts
const cfg_s = struct {
    mainkey_path: []u8,
    procfs_path: []u8,
    fake_time: u64,
    interval: u64,
    verbose: bool,
    verbose_leaky: bool,
    dry_run: bool,
    one_shot: bool,

    fn init(alloc: Allocator) !*cfg_s {
        var self = try alloc.create(cfg_s);
        self.mainkey_path = undefined;
        self.procfs_path = undefined;
        self.fake_time = 0;
        self.interval = DEF_IVAL;
        self.verbose = false;
        self.verbose_leaky = false;
        self.dry_run = false;
        self.one_shot = false;
        try self._parse_args(alloc);
        return self;
    }

    fn _usage(comptime format: []const u8, args: anytype) noreturn {
        log.err(format, args);
        const usage_fmt =
            \\
            \\Usage: tofurkey [-vno] [-i seconds] [-a {s}] [-k /path/to/main/secret]
            \\  -k Path to long-term main secret file generated and distributed to a
            \\     cluster by the administrator. This file must exist and have at least
            \\     32 bytes of secret high-entropy binary data, and will be re-read every
            \\     time TFO keys are generated. Mutually exclusive with -a. If this option
            \\     is not provided, then the -a autokey mode is the default.
            \\  -a Custom pathname to persist an auto-generated key, defaults to
            \\     '{s}'. This file will be created if it's missing
            \\     and persisted across runs, but perhaps not across reboots at the
            \\     default path, and obviously affords no possibility of distributed
            \\     sync across a cluster. Mutually exclusive with -k.
            \\  -i Interval seconds for key rotation, default is {d}, allowed range
            \\     is {d} - {d}, must be even. Daemon wakes up to rotate keys at
            \\     every half-interval of unix time to manage validity overlaps.
            \\     Intervals *must* match across a cluster to get the same keys!
            \\  -v Verbose output to stderr
            \\  -n Dry-run mode - Data is not actually written to procfs, but everything
            \\     else still happens
            \\  -o One-shot mode - it will calculate the current keys and set them once
            \\     and then exit. Normal mode is to remain running and rotate keys on
            \\     timer intervals forever.
            \\
            \\This is tofurkey v1.2.0 (EXPERIMENTAL Zig variant)
            \\tofurkey is a tool for distributed sync of Linux TCP Fastopen key rotations
            \\More info is available at https://github.com/blblack/tofurkey
            \\
        ;
        const usage_args = .{ def_autokey_path, def_autokey_path, DEF_IVAL, MIN_IVAL, MAX_IVAL };
        std.io.getStdErr().writer().print(usage_fmt, usage_args) catch {};
        posix.exit(2);
    }

    fn _parse_args(self: *cfg_s, alloc: Allocator) !void {
        var arg_autokey: ?[*:0]const u8 = null;
        var arg_mainkey: ?[*:0]const u8 = null;
        var arg_procfs: ?[*:0]const u8 = null;
        var goi = getopt.getopt(posix.argv, ":k:i:P:T:a:vVno");
        while (goi.next()) |optchar| {
            switch (optchar) {
                'v' => self.verbose = true,
                'n' => self.dry_run = true,
                'o' => self.one_shot = true,
                'k' => arg_mainkey = goi.getOptArg().?,
                'a' => arg_autokey = goi.getOptArg().?,
                'i' => {
                    const arg = goi.getOptArg().?;
                    const i = std.fmt.parseInt(u64, std.mem.span(arg), 10) catch {
                        _usage("Cannot parse '{s}' as u64", .{arg});
                    };
                    if (i < MIN_IVAL or i > MAX_IVAL or ((i & 1) != 0))
                        _usage("Interval value {d} is out of range or odd", .{i});
                    self.interval = i;
                },
                // These three are just for testsuite/debugging:
                'P' => arg_procfs = goi.getOptArg().?,
                'V' => {
                    self.verbose = true;
                    self.verbose_leaky = true;
                },
                'T' => {
                    const arg = goi.getOptArg().?;
                    const t = std.fmt.parseInt(u64, std.mem.span(arg), 10) catch {
                        _usage("Cannot parse '{s}' as u64", .{arg});
                    };
                    if (t < MIN_REAL_TIME or t > MAX_REAL_TIME)
                        _usage("Faketime value {d} is out of range", .{t});
                    self.fake_time = t;
                    self.one_shot = true;
                },
                // Error cases
                '?' => _usage("Invalid Option '-{c}'", .{goi.getOptOpt()}),
                ':' => _usage("Missing argument for '-{c}'", .{goi.getOptOpt()}),
                else => unreachable,
            }
        }

        if (goi.getOptInd() != posix.argv.len)
            _usage("Excess unknown CLI arguments after options", .{});

        // Handle path string defaulting and autokey logic, etc
        if (arg_procfs) |arg| {
            self.procfs_path = try alloc.dupe(u8, std.mem.span(arg));
        } else {
            self.procfs_path = try alloc.dupe(u8, def_procfs_path);
        }

        if (arg_mainkey != null and arg_autokey != null)
            _usage("Cannot set both -k and -a", .{});

        var mainkey_path: [:0]const u8 = undefined;
        if (arg_mainkey != null) {
            mainkey_path = std.mem.span(arg_mainkey.?);
        } else if (arg_autokey != null) {
            mainkey_path = std.mem.span(arg_autokey.?);
        } else {
            mainkey_path = def_autokey_path;
        }

        if (mainkey_path.len == 0)
            _usage("Key path arguments cannot be empty strings", .{});
        if (mainkey_path[mainkey_path.len - 1] == '/')
            _usage("Key path arguments cannot have a trailing slash", .{});

        self.mainkey_path = try alloc.dupe(u8, mainkey_path);

        if (arg_mainkey == null)
            try autokey_setup(self.mainkey_path);
    }

    fn deinit(self: *const cfg_s, alloc: Allocator) void {
        alloc.free(self.mainkey_path);
        alloc.free(self.procfs_path);
        alloc.destroy(self);
    }
};

// The inner, security-sensitive part of set_keys()
fn set_keys_secure(cfg: *const cfg_s, now: u64, ctr_primary: u64, ctr_backup: u64) !void {
    // Block signals while dealing with secure memory so that we always wipe
    // before exiting on a clean terminating signal
    const oldmask = block_all_signals();
    defer restore_signals(oldmask);

    var key_ascii: [TFO_ASCII_ALLOC]u8 = undefined;
    defer crypto.utils.secureZero(u8, &key_ascii);
    {
        var key_primary: [TFO_KEY_LEN]u8 = undefined;
        var key_backup: [TFO_KEY_LEN]u8 = undefined;
        defer crypto.utils.secureZero(u8, &key_primary);
        defer crypto.utils.secureZero(u8, &key_backup);
        {
            var key_main: [KDF_KEYBYTES]u8 = undefined;
            defer crypto.utils.secureZero(u8, &key_main);
            try safe_read_key(&key_main, cfg.mainkey_path);
            blake2b_kdf(&key_primary, ctr_primary, &key_main);
            blake2b_kdf(&key_backup, ctr_backup, &key_main);
        }
        try convert_keys_ascii(&key_ascii, &key_primary, &key_backup);
    }

    if (cfg.verbose_leaky)
        log.info("Generated ASCII TFO keys for procfs write: [{d}] {s}", .{ now, &key_ascii });
    if (!cfg.dry_run)
        try safe_write_procfs(&key_ascii, cfg.procfs_path);
}

// Do the idempotent key generation + deployment based on current wall clock
// (even if it's not exactly when we would've woken up), then returns the next
// time we should wake up to rotate
fn set_keys(cfg: *const cfg_s, now: u64) !u64 {
    log.info("Setting keys for unix time {d}", .{now});
    const tc = timecalc(now, cfg.interval);
    try set_keys_secure(cfg, now, tc.ctr_primary, tc.ctr_backup);
    if (cfg.dry_run and cfg.verbose)
        log.info("Did not write to procfs because dry-run (-n) was specified", .{});
    return tc.next_wake;
}

pub fn main() !void {
    if (os.linux.geteuid() == 0)
        try lsys.mlockall(lsys.MCL.CURRENT | lsys.MCL.FUTURE | lsys.MCL.ONFAULT);
    const rlzero = posix.rlimit{ .cur = 0, .max = 0 };
    try posix.setrlimit(.CORE, rlzero);

    // plain GPA for config/path/etc
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = general_purpose_allocator.allocator();

    const cfg: *const cfg_s = try cfg_s.init(alloc);
    defer cfg.deinit(alloc);

    // Initially set keys to whatever the current wall clock dictates, and exit
    // immediately if one-shot mode
    const initial_now = if (cfg.fake_time != 0) cfg.fake_time else try realtime_u64();
    var next_wake = try set_keys(cfg, initial_now);
    if (cfg.one_shot) {
        log.info("Exiting due to one-shot mode (-o flag)", .{});
        return;
    }

    // For the long-running case, notify systemd of readiness after the initial
    // setting of keys above.
    try sysd_notify_ready();

    // We hang out in this time loop until something kills us
    if (cfg.verbose)
        log.info("Will set keys at each half-interval, when unix_time % {d} ~= 2", .{cfg.interval / 2});
    while (true) {
        const next_fudged = next_wake + FUDGE_S;
        if (cfg.verbose)
            log.info("Sleeping until next half-interval wakeup at {d}", .{next_fudged});
        try lsys.clock_nanosleep(posix.CLOCK.REALTIME, lsys.TIMER.ABSTIME, next_fudged, FUDGE_NS);
        next_wake = try set_keys(cfg, try realtime_u64());
    }
}

test {
    // Make sure we run unit tests in our other local import files
    std.testing.refAllDecls(getopt);
    std.testing.refAllDecls(lsys);
}
