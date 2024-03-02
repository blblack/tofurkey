// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

// This file encapsulates all our direct uses of libc and libsodium into
// more zig-like interfaces for the main code.

const std = @import("std");
const assert = std.debug.assert;
// Handle 0.11.0->0.12-dev switch from "os" to "posix"
const posix = if (@hasDecl(std, "posix")) std.posix else std.os;
const c = @cImport({
    @cInclude("time.h"); // clock_nanosleep()
    @cInclude("sodium.h"); // libsodium
});

pub fn clock_nanosleep_real_abs(sec: u64, nsec: u64) !void {
    // Assert that time_t (type of .tv_sec) can hold the same positive range as
    // i64. This code is intentionally not compatible with 32-bit time_t!
    comptime {
        assert(std.math.maxInt(c.time_t) >= std.math.maxInt(i64));
    }
    // Assert the caller limits "sec" to not saturate i64 as well
    assert(sec < std.math.maxInt(i64));
    const ts = c.struct_timespec{ .tv_sec = @intCast(sec), .tv_nsec = @intCast(nsec) };
    const rv = c.clock_nanosleep(c.CLOCK_REALTIME, c.TIMER_ABSTIME, &ts, null);
    if (rv != 0)
        return error.ClockNanosleepFailed;
}

test "clock_nanosleep sanity" {
    // Get current time and sleep until then, with the nsec truncated to zero.
    // Should return without any significant delay.
    var ts = posix.timespec{ .tv_sec = 0, .tv_nsec = 0 };
    try posix.clock_gettime(posix.CLOCK.REALTIME, &ts);
    if (ts.tv_sec < 0)
        return error.TimeRange;
    try clock_nanosleep_real_abs(@intCast(ts.tv_sec), 0);
}

//-----------------
// libsodium stuff
//-----------------

pub const b2b_CONTEXTBYTES = c.crypto_kdf_blake2b_CONTEXTBYTES;
pub const b2b_KEYBYTES = c.crypto_kdf_blake2b_KEYBYTES;
pub const b2b_BYTES_MIN = c.crypto_kdf_blake2b_BYTES_MIN;
pub const b2b_BYTES_MAX = c.crypto_kdf_blake2b_BYTES_MAX;

pub fn sodium_init() !void {
    if (c.sodium_init() < 0)
        return error.SodiumInitFailed;
}

pub fn sodium_memzero(mem: []u8) void {
    c.sodium_memzero(@as(*anyopaque, @ptrCast(mem.ptr)), mem.len);
}

pub fn sodium_rand(mem: []u8) void {
    c.randombytes_buf(@as(*anyopaque, @ptrCast(mem.ptr)), mem.len);
}

pub fn b2b_derive_from_key(out: *[16]u8, len: usize, subkey: u64, ctx: *const [8]u8, key: *const [32]u8) !void {
    const rv = c.crypto_kdf_blake2b_derive_from_key(out, len, subkey, ctx, key);
    if (rv != 0)
        return error.Blake2BFailed;
}

test "blake2b KDF alg check" {
    var outbuf: [16]u8 = undefined;
    const ctx = [_]u8{ 't', 'o', 'f', 'u', 'r', 'k', 'e', 'y' };
    const key = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };
    try b2b_derive_from_key(&outbuf, 16, 1234, &ctx, &key);
    const expect_out = [_]u8{
        0x0E, 0xB0, 0x0F, 0x64, 0x3E, 0xB0, 0x4E, 0x60,
        0x9D, 0x5B, 0x23, 0x18, 0xEB, 0x67, 0x52, 0x31,
    };
    try std.testing.expectEqualSlices(u8, &expect_out, &outbuf);
}
