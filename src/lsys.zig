// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

// A place to put missing posix interfaces that wrap Linux syscalls, and
// implement the interfaces in native Zig.  Everything here could be obviated
// by upstream changes in Zig std, but the versions I've placed here may be
// minimal and/or specific to this project and/or not generic enough (yet).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

// -------------------
// These bits would go in lib/std/os/linux.zig (without the _ prefix on the call):
// -------------------

const arch = builtin.cpu.arch;
pub const MCL = if (arch.isPowerPC() or arch.isSPARC()) packed struct(u32) {
    _0: u13 = 0,
    CURRENT: bool = false,
    FUTURE: bool = false,
    ONFAULT: bool = false,
    _17: u16 = 0,
} else packed struct(u32) {
    CURRENT: bool = false,
    FUTURE: bool = false,
    ONFAULT: bool = false,
    _: u29 = 0,
};

pub const timer_t = enum(u32) {
    RELTIME = 0,
    ABSTIME = 1,
};

pub fn _mlockall(flags: MCL) usize {
    return std.os.linux.syscall1(.mlockall, @as(u32, @bitCast(flags)));
}

pub fn _clock_nanosleep(clk_id: std.os.linux.clockid_t, flags: timer_t, req: *const posix.timespec, rem: ?*posix.timespec) usize {
    return std.os.linux.syscall4(.clock_nanosleep, @as(usize, @intFromEnum(clk_id)), @as(usize, @intFromEnum(flags)), @intFromPtr(req), @intFromPtr(rem));
}

// -------------------
// These bits would go in lib/std/posix.zig and are the real public interface
// -------------------

pub fn mlockall(flags: MCL) !void {
    switch (posix.errno(_mlockall(flags))) {
        .SUCCESS => return,
        .INVAL => return error.InvalidArgument,
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

// Note I've copied the auto-handling of EINTR and the arguments style from a
// combination of std's existing clock_gettime() and nanosleep(), but modified
// to handle the ABSTIME case as well.  errno is slightly-different too, and
// AFAIK Darwin doesn't have this syscall.
pub fn clock_nanosleep(clk_id: std.os.linux.clockid_t, flags: timer_t, seconds: u64, nanoseconds: u64) !void {
    var req = posix.timespec{
        .sec = std.math.cast(isize, seconds) orelse std.math.maxInt(isize),
        .nsec = std.math.cast(isize, nanoseconds) orelse std.math.maxInt(isize),
    };
    var rem: posix.timespec = undefined;
    while (true) {
        switch (posix.errno(_clock_nanosleep(clk_id, flags, &req, &rem))) {
            .SUCCESS => return,
            .INTR => {
                if (flags != .ABSTIME)
                    req = rem;
                continue;
            },
            .INVAL, .OPNOTSUPP => return error.UnsupportedClock,
            .FAULT => unreachable,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

test "clock_nanosleep basic smoke" {
    // Get current time and sleep absolutely until then, with the nsec
    // truncated to zero. This should return "immediately"
    var ts: posix.timespec = undefined;
    try posix.clock_gettime(.REALTIME, &ts);
    try clock_nanosleep(.REALTIME, .ABSTIME, @intCast(ts.sec), 0);
}
