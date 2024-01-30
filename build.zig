const std = @import("std");
pub fn build(b: *std.Build) void {
    // Standard options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Define the executable.
    // Later after dropping 0.11.0 support, can fold this up the "normal" way
    // with addExecutable(.{ ... }))
    var exe_opts = std.Build.ExecutableOptions{
        .name = "tofurkey",
        .root_source_file = .{ .path = "src/tofurkey.zig" },
        .single_threaded = true,
        .target = target,
        .optimize = optimize,
    };
    if (@hasField(std.Build.ExecutableOptions, "strip")) // Not present in 0.11.0
        exe_opts.strip = (optimize != .Debug);
    const exe = b.addExecutable(exe_opts);

    // Support for -Drundir=x affecting executable via config import
    const rundir = b.option([]const u8, "rundir", "The system rundir, default '/run', for autokey storage") orelse "/run";
    const options = b.addOptions();
    options.addOption([]const u8, "rundir", rundir);
    if (@hasDecl(@TypeOf(exe.*), "addOptions")) {
        exe.addOptions("config", options); // 0.11.0
    } else {
        exe.root_module.addOptions("config", options); // master 0.12.0-dev
    }

    // Link libsodium and libc for the executable
    exe.linkSystemLibrary("sodium");
    exe.linkLibC();

    // Declare the built executable as installable and put it in an overrideable sbindir
    const sbindir = b.option([]const u8, "sbindir", "Prefix-relative subpath for sbin dir, default 'sbin'") orelse "sbin";
    const exe_art = b.addInstallArtifact(exe, .{ .dest_dir = .{ .override = .{ .custom = sbindir } } });
    b.getInstallStep().dependOn(&exe_art.step);

    // Install the manpage as well, with support for overriding the
    // prefix-relative destination directory:
    const man8dir = b.option([]const u8, "man8dir", "Prefix-relative subpath for man8 dir, default 'share/man/man8'") orelse "share/man/man8";
    const man_page = b.addInstallFileWithDir(.{ .path = "tofurkey.8" }, .{ .custom = man8dir }, "tofurkey.8");
    b.getInstallStep().dependOn(&man_page.step);

    // "zig build test" -> Unit testing
    const unit_exe = b.addTest(.{
        .root_source_file = .{ .path = "src/tofurkey.zig" },
        .single_threaded = true,
        .target = target,
        .optimize = optimize,
    });
    unit_exe.linkSystemLibrary("sodium");
    unit_exe.linkLibC();
    const run_unit_tests = b.addRunArtifact(unit_exe);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // "zig build itest" -> Quick integration testing with t/quick.sh
    const itest_step = b.step("itest", "Run quick integration tests");
    const itest_run_quick = b.addSystemCommand(&.{"t/quick.sh"});
    itest_run_quick.addArtifactArg(exe);
    itest_step.dependOn(&itest_run_quick.step);

    // "zig build itest-slow" -> Full integration testing with t/quick.sh + t/slow.sh
    const itest_step_slow = b.step("itest-slow", "Run full integration tests (slower)");
    const itest_run_slow = b.addSystemCommand(&.{"t/slow.sh"});
    itest_run_slow.addArtifactArg(exe);
    itest_step_slow.dependOn(&itest_run_slow.step);
    itest_step_slow.dependOn(&itest_run_quick.step);
}
