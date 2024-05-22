// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

const std = @import("std");
pub fn build(b: *std.Build) void {
    // Standard options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{
        .name = "tofurkey",
        .root_source_file = b.path("src/tofurkey.zig"),
        .single_threaded = true,
        .target = target,
        .optimize = optimize,
        .strip = (optimize != .Debug),
    });

    // Support for -Drundir=x affecting executable via config import
    const rundir = b.option([]const u8, "rundir", "The system rundir, default '/run', for autokey storage") orelse "/run";
    const options = b.addOptions();
    options.addOption([]const u8, "rundir", rundir);
    exe.root_module.addOptions("config", options);

    // Declare the built executable as installable and put it in an overrideable sbindir
    const sbindir = b.option([]const u8, "sbindir", "Prefix-relative subpath for sbin dir, default 'sbin'") orelse "sbin";
    const exe_art = b.addInstallArtifact(exe, .{ .dest_dir = .{ .override = .{ .custom = sbindir } } });
    b.getInstallStep().dependOn(&exe_art.step);

    // Install the manpage as well, with support for overriding the
    // prefix-relative destination directory:
    const man8dir = b.option([]const u8, "man8dir", "Prefix-relative subpath for man8 dir, default 'share/man/man8'") orelse "share/man/man8";
    const man_page = b.addInstallFileWithDir(b.path("tofurkey.8"), .{ .custom = man8dir }, "tofurkey.8");
    b.getInstallStep().dependOn(&man_page.step);

    // "zig build test" -> Unit testing
    const unit_exe = b.addTest(.{
        .root_source_file = b.path("src/tofurkey.zig"),
        .single_threaded = true,
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_exe);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // "zig build itest" -> Quick integration testing with t/itest.sh
    const itest_step = b.step("itest", "Run quick integration tests");
    const itest_run_quick = b.addSystemCommand(&.{"t/itest.sh"});
    itest_run_quick.addArtifactArg(exe);
    itest_step.dependOn(&itest_run_quick.step);

    // "zig build itest-slow" -> Full integration testing with t/itest.sh -s
    const itest_step_slow = b.step("itest-slow", "Run full integration tests (slower)");
    const itest_run_slow = b.addSystemCommand(&.{"t/itest.sh"});
    itest_run_slow.addArg("-s");
    itest_run_slow.addArtifactArg(exe);
    itest_step_slow.dependOn(&itest_run_slow.step);
}
