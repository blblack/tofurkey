// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

const std = @import("std");

/// This is a Zig-ified implementation of the spirit and mechanics of the POSIX
/// getopt(3) interface.   It has the POSIX-mandated behaviors, but behind a
/// better interface that doesn't use global variables. The goal here is to
/// make it easy to port existing C code which uses POSIX getopt to Zig. This
/// implementation does not support GNU extensions or long options.
///
/// Basic cheat sheet for porting:
///
///     Normal POSIX/C getopt()                || Zig getopt()
///     ---------------------------------------------------------------------
///     while((f = getopt(argc, argv, "abc"))  || var o = getopt(std.posix.argv, "abc");
///                != -1) { ... }              || while(o.next()) |f| { ... }
///     char* x = optarg;                      || var x = o.getOptArg().?;
///     char c = optopt;                       || var c = o.getOptOpt();
///     int i = optind;                        || var i = o.getOptInd();
///     opterr = 0;                            || o.setOptErr(false);
///     optind = 0; // non-standard            || [just make a new object]
///
pub fn getopt(args: []const [*:0]const u8, optstr: [:0]const u8) GetOptIterator {
    return GetOptIterator{
        ._argv = args,
        ._optstr = optstr,
        ._colon_mode = (optstr.len > 0 and optstr[0] == ':'),
    };
}

/// This is the option iterator returned by getopt()
pub const GetOptIterator = struct {
    // These states are constant for the life of the iterator:
    _argv: []const [*:0]const u8 = undefined,
    _optstr: []const u8 = undefined,

    // Caches the fact that optstr[0] == ':' at iterator creation.
    _colon_mode: bool = false,

    // indexes argv itself and starts at argv[1]
    _optind: usize = 1,

    // indexes characters within the current argv elem
    _nextc: usize = 0,

    // Controls getopt() stderr output on bad options or missing args. Defaults
    // on and can be toggled via .setOptErr(), but a leading colon in optstr
    // overrides this (effectively forcing it false).
    _opterr: bool = true,

    // These are outputs fetched via .getOptArg() and .getOptOpt()
    _optarg: ?[*:0]const u8 = undefined,
    _optopt: u8 = '?',

    // This pattern for robust stderr output copied from std.log.defaultLog():
    fn _perr(comptime format: []const u8, args: anytype) void {
        const stderr = std.io.getStdErr().writer();
        var bw = std.io.bufferedWriter(stderr);
        const writer = bw.writer();
        std.debug.getStderrMutex().lock();
        defer std.debug.getStderrMutex().unlock();
        nosuspend {
            writer.print(format ++ "\n", args) catch return;
            bw.flush() catch return;
        }
    }

    /// Get the next flag character as ?u8, returns null if none left.
    ///
    /// Returns '?' for an invalid option (get the offending flag from
    /// .getOptOpt()).
    ///
    /// Returns '?' (or ':' if leading char of optopt was ':') on a valid
    /// option which was missing its required argument because we reached the
    /// end of argv (get the offending option from .getOptOpt()).
    pub fn next(self: *GetOptIterator) ?u8 {
        // If there's no args left there's nothing to do!
        if (self._optind >= self._argv.len)
            return null;

        // Reset our single-shot conditional output states to sane values
        self._optarg = null;
        self._optopt = '?';

        const do_stderr = if (self._colon_mode) false else self._opterr;
        const elem = self._argv[self._optind]; // current argv element

        // If we're starting a new argv element:
        if (self._nextc == 0) {
            // If "--", skip this element and return null (end of getopt args)
            if (elem[0] == '-' and elem[1] == '-' and elem[2] == 0) {
                self._optind += 1;
                return null;
            }

            // If "-" or anything that doesn't start with a dash, return null (end of getopt args)
            if (elem[0] != '-' or elem[1] == 0)
                return null;

            // We have at least one flag to parse, set nextc past the leading '-'
            self._nextc = 1;
        }

        // Grab the next option flag from this elem
        var flag = elem[self._nextc];
        self._nextc += 1;

        // Did we consume the final character of the current elem above?
        const final_char = (elem[self._nextc] == 0);

        // See if we can find the flag in our optstr
        const maybe_optstr_idx = std.mem.indexOfScalar(u8, self._optstr, flag);

        // If we can't find it, or we matched ':' (which has special meaning in
        // optstr and therefore can't be an option flag), deal with error:
        if (maybe_optstr_idx == null or flag == ':') {
            if (do_stderr)
                _perr("{s}: invalid option -- '{c}'", .{ self._argv[0], flag });
            self._optopt = flag;
            // Maintain state for sanity and possible recovery
            if (final_char) {
                self._optind += 1;
                self._nextc = 0;
            }
            return '?';
        }

        // From here on we know we have a legitimate flag character
        const optstr_idx = maybe_optstr_idx.?;

        // where the following ':' would be in optstr if flag requires an arg
        const next_optstr_idx = optstr_idx + 1;

        // The non-argument case, just a simple boolean flag, return early
        if (next_optstr_idx >= self._optstr.len or self._optstr[next_optstr_idx] != ':') {
            if (final_char) {
                self._optind += 1;
                self._nextc = 0;
            }
            return flag;
        }

        // From here down we're trying to set optarg to a required flag argument:
        if (final_char) {
            // If final_char, then the optarg is the next argv elem:
            self._optind += 1;
            if (self._optind < self._argv.len) {
                self._optarg = self._argv[self._optind];
            } else {
                if (do_stderr)
                    _perr("{s}: option requires an argument -- '{c}'", .{ self._argv[0], flag });
                self._optopt = flag;
                flag = if (self._colon_mode) ':' else '?';
            }
        } else {
            // For a non-final character, use the rest of elem as optarg:
            self._optarg = elem[self._nextc.. :0];
        }

        // inc optind and reset nextc for consumed arg
        self._optind += 1;
        self._nextc = 0;
        return flag;
    }

    /// Gets the argument string for a returned flag which required an argument
    pub fn getOptArg(self: *GetOptIterator) ?[*:0]const u8 {
        return self._optarg;
    }

    /// Gets the offending option character in error cases when .next()
    /// returns either '?' or ':'
    pub fn getOptOpt(self: *GetOptIterator) u8 {
        return self._optopt;
    }

    /// When called after .next() returns null, gives the argv index it stopped
    /// processing at.  You may use this to manually iterate further non-getopt
    /// arguments.
    pub fn getOptInd(self: *GetOptIterator) usize {
        return self._optind;
    }

    /// This can be used to turn off stderr outputs from .next() by setting
    /// false, or to turn them back on (default) by setting true.
    ///
    /// If the optstr starts with ':', this overrides opterr and permanently
    /// disables stderr outputs.
    pub fn setOptErr(self: *GetOptIterator, opterr: bool) void {
        self._opterr = opterr;
    }
};

test getopt {
    var verbose: bool = false;
    var iarg: [*:0]const u8 = undefined;
    var extra_args: usize = 0;

    const myargv = [_][*:0]const u8{
        "myprogram", "-i", "1234", "-v", "--", "foo",
    };

    // In a real program, you'd probably pass std.posix.argv instead of &myargv
    var goi = getopt(&myargv, ":vi:");
    while (goi.next()) |flag| {
        switch (flag) {
            'v' => verbose = true,
            'i' => iarg = goi.getOptArg().?,
            '?' => std.debug.print("Invalid Option '-{c}'\n", .{goi.getOptOpt()}),
            ':' => std.debug.print("Missing argument for '-{c}'\n", .{goi.getOptOpt()}),
            else => unreachable,
        }
    }
    var optind = goi.getOptInd();
    while (optind < myargv.len) {
        // std.debug.print("Extra arg after getopt: '{s}'\n", .{myargv[optind]});
        extra_args += 1;
        optind += 1;
    }

    try std.testing.expect(verbose);
    try std.testing.expect(extra_args == 1);
    try std.testing.expectEqualStrings("1234", std.mem.span(iarg));
}

test "getopt - exercise interfaces + code paths" {
    const myargv = [_][*:0]const u8{
        "myprogram", "-vxasdf", "-i1234", "-A",
        "-vn",       "-s",      "foo",    "-v",
        "-",         "extra2",
    };
    var vcount: usize = 0;
    var ncount: usize = 0;
    var goi = getopt(&myargv, "vni:x:s:");
    try std.testing.expectEqual(true, goi._opterr);
    goi.setOptErr(false);
    try std.testing.expectEqual(false, goi._opterr);
    while (goi.next()) |flag| {
        switch (flag) {
            'v' => vcount += 1,
            'n' => ncount += 1,
            'i' => try std.testing.expectEqualStrings("1234", std.mem.span(goi.getOptArg().?)),
            'x' => try std.testing.expectEqualStrings("asdf", std.mem.span(goi.getOptArg().?)),
            's' => try std.testing.expectEqualStrings("foo", std.mem.span(goi.getOptArg().?)),
            '?' => try std.testing.expect('A' == goi.getOptOpt()),
            ':' => std.debug.print("Missing argument for '-{c}'\n", .{goi.getOptOpt()}),
            else => unreachable,
        }
    }
    var myoptind = goi.getOptInd();
    try std.testing.expect(myoptind < myargv.len);
    try std.testing.expect((myargv.len - myoptind) == 2);
    try std.testing.expectEqualStrings("-", std.mem.span(myargv[myoptind]));
    myoptind += 1;
    try std.testing.expectEqualStrings("extra2", std.mem.span(myargv[myoptind]));
    try std.testing.expect(vcount == 3);
    try std.testing.expect(ncount == 1);
}
