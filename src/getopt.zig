// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

// ---
// TODO: Whip this into a more-proper shape for upstreaming into Zig std
// somewhere?  At least the naming, namespacing, and interface style are
// probably not quite right for that yet.  Also, as a POSIXy approximation with
// a somewhat different looking interface than the (horrible by Zig standards)
// actual POSIX interface, does it belong in std.posix or std.elsewhere?
// ---

// The real POSIX standard interface for getopt() is basically a function that
// is called repeatedly with (hopefully consistent!) arguments "argc", "argv",
// and "optstr". That interface also has four public, process-global variables
// used for input and output with the caller between calls, one of which also
// serves as part of the "internal" state of getopt():
//   int optind - Carries state across calls, used by caller as a getopt()
//     output in some cases (e.g. to detect whether additional non-getopt
//     options remain at the end of argv). Callers can also set this to zero
//     between calls to reset the state of getopt() to the start of argv in
//     some implementations, although POSIX leaves this unspecified.
//   int optopt - Output-only, contains the offending option flag character
//     when certain errors are signalled by the getopt return value.
//   int opterr - Defaults to true, controls whether getopt() emits error
//     messages to stderr, can be changed by the user between calls. If the
//     optstr starts with ':', this variable is ignored and output is always
//     suppressed.
//   char* optarg - Output-only, has a pointer to the argument string after
//     getopt returns an option flag which optstr specified as requiring an
//     argument string. Unspecified and arguably an interface misuse to read
//     this in any other state.
//
// This implementation attempts saner interpretation of the getopt interface
// which does *not* use or reference any public global variables directly, but
// otherwise adheres to the standards set forth by POSIX getopt in spirit, with
// a goal of making it easy to port existing getopt()-based C code to Zig.  It
// does not support GNU extensions or long options.
//
// In this interface, getopt(std.posix.argv, optstr) is called just once for
// initialization and returns an iterator object with private internal state.
// The iterator's .next() function has the return type ?u8 and can be used in a
// while loop similarly to the legacy POSIX getopt() call (with the null return
// taking the place of POSIX -1). Other iterator functions provide equivalents
// of the normal uses of the POSIX global variables.

const std = @import("std");

pub const GetOptIterator = struct {
    // These states are constant for the life of the iterator:
    _argv: []const [*:0]const u8 = undefined,
    _optstr: []const u8 = undefined,

    // _nextc is internal variable state carried across iterations. It
    // indexes the current argv[optind] to keep track of where we're at in
    // the midst of multiple short flags like "-nvoX". If zero, we're
    // starting on a fresh argv element.
    _nextc: usize = 0,

    // _optind indexes argv itself and is also internal state carried across
    // iterations. Users can reset optind (which also resets nextc above for
    // a full reset) via the interface .resetOptInd(), which is equivalent
    // to setting the global optind to zero in legacy implementations.
    _optind: usize = 1,

    // According to POSIX, caller can control the opterr (change it between
    // iterations), and we provide an interface to do so. We implement the
    // standard behavior here: the default of "true" means getopt will emit
    // error messages to stderr, while false suppresses them. However,
    // regardless of this flag, if optstr's first character is ':', error
    // messages are always suppressed.
    _opterr: bool = true,

    // Caches the fact that optstr[0] == ':' at iterator creation.  This
    // affects stderr messages as noted above, and also changes the getopt()
    // result character from '?' to ':' when a required argument to an
    // option is missing (because the option was at the end of the last argv
    // element).
    _colon_mode: bool = false,

    // These are really single-iteration, output-only state, but they're
    // carried to the user via getOptArg() and getOptOpt() to mimic the POSIX
    // getopt() interface
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

    pub fn next(self: *GetOptIterator) ?u8 {
        // If optstr is empty, what's the point?
        if (self._optstr.len == 0)
            return null;

        // If there's nothing beyond argv[0], there's nothing to do!
        if (self._argv.len < 2)
            return null;

        // If there's no argv elems left, return null regardless of other state
        if (self._optind >= self._argv.len)
            return null;

        // colon_mode == true always suppresses errors, otherwise opterr is in
        // control (which defaults to emitting them, but can be controlled by
        // caller):
        const do_stderr = if (self._colon_mode) false else self._opterr;

        // Re-set one-shot outputs on every iteration.
        self._optarg = null;
        self._optopt = '?';

        // Shorthand for the argv element under examination
        const elem = self._argv[self._optind];

        // If we're at the start of a new argv element:
        if (self._nextc == 0) {
            // If elem seems to be "--", skip past it and return null (end of
            // getopt options, but could be other non-getopt argv elements the
            // caller wants to consume)
            if (elem[0] == '-' and elem[1] == '-' and elem[2] == 0) {
                self._optind += 1;
                return null;
            }

            // If elem either doesn't start with '-', or is just a lone "-"
            // string, do *not* skip it and do return null (end of getopt
            // options, but this and anything after it could be non-getopt
            // argv elements the caller wants to consume)
            if (elem[0] != '-' or elem[1] == 0)
                return null;

            // If we get here, there's at *least* one option flag to handle
            // within this argv elem. Set _nextc to point just after the
            // leading '-', at the flag char itself:
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
        // optstr and therefore can't be an option flag), deal with it as
        // an error:
        if (maybe_optstr_idx == null or flag == ':') {
            if (do_stderr)
                _perr("{s}: invalid option -- '{c}'", .{ self._argv[0], flag });
            self._optopt = flag;
            // We still maintain proper state, primarily to avoid an infinite
            // while() loop if the caller doesn't terminate the loop on '?',
            // but also it allows continuing after such an error in some
            // limited cases.
            if (final_char) {
                self._optind += 1;
                self._nextc = 0;
            }
            return '?';
        }

        // From here on we know we have a legitimate flag character
        const optstr_idx = maybe_optstr_idx.?;

        // where the trailing ':' would be in optstr if arg required
        const next_optstr_idx = optstr_idx + 1;

        // The non-argument case, just a simple boolean flag
        if (next_optstr_idx >= self._optstr.len or self._optstr[next_optstr_idx] != ':') {
            // reset nextc and inc optind iff final_char so the next iteration
            // starts on the next argv elem
            if (final_char) {
                self._optind += 1;
                self._nextc = 0;
            }
            return flag;
        }

        // If the flag requires an argument string, setup optarg and return the
        // flag (or error if the argument is missing)
        if (final_char) {
            // If flag was final char of an elem, increment optind to next
            // element to find the argument string:
            self._optind += 1;
            if (self._optind < self._argv.len) {
                self._optarg = self._argv[self._optind];
            } else {
                // No further argv elem to use as optarg:
                if (do_stderr)
                    _perr("{s}: option requires an argument -- '{c}'", .{ self._argv[0], flag });
                self._optopt = flag;
                flag = if (self._colon_mode) ':' else '?';
            }
        } else {
            // For a non-final character, use the rest of the current
            // element as the optarg:
            const len = std.mem.span(elem).len;
            self._optarg = elem[self._nextc..len :0];
            // ^ 0.11.0 requires above method, but 0.12+ allows:
            // self._optarg = elem[self._nextc.. :0];
        }
        // In all cases above, inc optind and reset nextc because we've
        // fully consumed an argv element as optarg, or we've reached end.
        // Either way:
        self._optind += 1;
        self._nextc = 0;
        return flag;
    }

    // Various accessors emulating common and/or standard caller usages of the
    // POSIX global variables:

    pub fn getOptArg(self: *GetOptIterator) ?[*:0]const u8 {
        return self._optarg;
    }

    pub fn getOptOpt(self: *GetOptIterator) u8 {
        return self._optopt;
    }

    pub fn getOptInd(self: *GetOptIterator) usize {
        return self._optind;
    }

    // POSIX mentions the ability of the user to modify optind between
    // iterations of getopt, but only specifically mentions resetting it to
    // zero with unspecified results of doing such a thing, so it's basically
    // up to implementations to decide what to do here. It seems common in the
    // real world that setting zero signals that the next iteration should
    // start over from a reset/initial state.  We support this behavior via
    // this interface.  Calling this is basically equivalent to "optind = 0".
    pub fn resetOptInd(self: *GetOptIterator) void {
        self._optind = 1;
        self._nextc = 0;
    }

    // opterr can be toggled on or off by the user to control getopt()'s
    // internal error messages to stderr. However, a leading colon in the
    // optstr always overrules opterr (IOW, if opterr is true but the leading
    // colon is present, output is still suppressed).
    pub fn getOptErr(self: *GetOptIterator) bool {
        return self._opterr;
    }

    pub fn setOptErr(self: *GetOptIterator, opterr: bool) void {
        self._opterr = opterr;
    }
};

pub fn getopt(argv: []const [*:0]const u8, optstr: [:0]const u8) GetOptIterator {
    return GetOptIterator{
        ._argv = argv,
        ._optstr = optstr,
        ._colon_mode = (optstr.len > 0 and optstr[0] == ':'),
    };
}

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
    goi.resetOptInd();
    try std.testing.expectEqual(false, goi._opterr);
    goi.setOptErr(true);
    try std.testing.expectEqual(true, goi._opterr);
    const firstopt_again: u8 = goi.next().?;
    try std.testing.expect('v' == firstopt_again);
    try std.testing.expect(goi.getOptArg() == null);
}
