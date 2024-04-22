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

const native_arch = builtin.cpu.arch;
const is_ppc = native_arch.isPPC();
const is_ppc64 = native_arch.isPPC64();
const is_sparc = native_arch.isSPARC();

pub const MCL = if (is_ppc or is_ppc64 or is_sparc) struct {
    pub const CURRENT = 0x2000;
    pub const FUTURE = 0x4000;
    pub const ONFAULT = 0x8000;
} else struct {
    pub const CURRENT = 0x01;
    pub const FUTURE = 0x02;
    pub const ONFAULT = 0x04;
};

pub const TIMER = struct {
    pub const ABSTIME = 0x01;
};

pub fn _mlockall(flags: i32) usize {
    return std.os.linux.syscall1(.mlockall, @as(usize, @bitCast(@as(isize, flags))));
}

pub fn _clock_nanosleep(clk_id: i32, flags: i32, req: *const posix.timespec, rem: ?*posix.timespec) usize {
    return std.os.linux.syscall4(.clock_nanosleep, @as(usize, @bitCast(@as(isize, clk_id))), @as(usize, @bitCast(@as(isize, flags))), @intFromPtr(req), @intFromPtr(rem));
}

// -------------------
// These bits would go in lib/std/posix.zig and are the real public interface
// -------------------

pub fn mlockall(flags: i32) !void {
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
pub fn clock_nanosleep(clk_id: i32, flags: i32, seconds: u64, nanoseconds: u64) !void {
    var req = posix.timespec{
        .tv_sec = std.math.cast(isize, seconds) orelse std.math.maxInt(isize),
        .tv_nsec = std.math.cast(isize, nanoseconds) orelse std.math.maxInt(isize),
    };
    var rem: posix.timespec = undefined;
    while (true) {
        switch (posix.errno(_clock_nanosleep(clk_id, flags, &req, &rem))) {
            .SUCCESS => return,
            .INTR => {
                if (flags != TIMER.ABSTIME)
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
    try posix.clock_gettime(posix.CLOCK.REALTIME, &ts);
    try clock_nanosleep(posix.CLOCK.REALTIME, TIMER.ABSTIME, @intCast(ts.tv_sec), @intCast(ts.tv_nsec));
}
