// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

// A place to put missing posix interfaces that wrap Linux syscalls, and
// implement the interfaces in native Zig.  Everything here could be obviated
// by upstream changes in Zig std, but the versions I've placed here may be
// minimal and/or specific to this project and/or not generic enough (yet).

const std = @import("std");
// Handle 0.11.0->0.12-dev switch from "os" to "posix"
const posix = if (@hasDecl(std, "posix")) std.posix else std.os;

// -------------------
// These bits would go in lib/std/os/linux.zig (without the hacky lsys_ prefix):
// -------------------

// These constants vary by hardware, but the values here seems to be correct
// for all except sparc, ppc, and alpha.  Good enough for me, for now.
pub const MCL = struct {
    pub const CURRENT = 0x01;
    pub const FUTURE = 0x02;
    pub const ONFAULT = 0x04;
};

pub fn _mlockall(flags: i32) usize {
    return std.os.linux.syscall1(.mlockall, @as(usize, @bitCast(@as(isize, flags))));
}

// -------------------
// These bits would go in lib/std/os.zig (aka posix) and are the real public interface
// -------------------

pub fn mlockall(flags: i32) !void {
    switch (posix.errno(_mlockall(flags))) {
        .SUCCESS => return,
        .INVAL => return error.InvalidArgument,
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}
