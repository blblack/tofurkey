DESTDIR ?=
prefix ?= /usr
exec_prefix ?= $(prefix)
sbindir ?= $(exec_prefix)/sbin
datarootdir ?= $(prefix)/share
mandir ?= $(datarootdir)/man
man8dir ?= $(mandir)/man8
rundir ?= /run

CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wconversion -Warith-conversion -Wshadow -Warray-bounds=2 -Wcast-align=strict -Wcast-qual -Werror=vla -Wfloat-equal -Wstrict-overflow=5 -Wstrict-aliasing
LDFLAGS ?=
LDLIBS ?= -lsodium

.PHONY: all clean distclean check test qa install
all: tofurkey
rundir.inc: Makefile
	echo "// Dynamically created by make\n#define RUNDIR \"$(rundir)\"" >$@
tofurkey: tofurkey.c rundir.inc Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@
clean:
	$(RM) rundir.inc
	$(RM) tofurkey
distclean: clean
check: tofurkey
	@t/quick.sh
	@if [ "$(SLOW_TESTS)"x != x ]; then t/slow.sh; fi
test: check
qa: tofurkey check
	@echo "===== Enforcing style (may alter source!) ... ====="
	qa/style.sh
	@echo "===== Running cppcheck ... ====="
	qa/cppcheck.sh
	@echo "===== Running clang analyzer ... ====="
	qa/scanbuild.sh
	@echo "===== Running tests under gcc sanitizers ... ====="
	qa/sanitizers.sh
	@echo "===== Running tests under valgrind ... ====="
	qa/valgrind.sh
install: tofurkey tofurkey.8
	install -D -s -m 755 -t $(DESTDIR)$(sbindir) tofurkey
	install -D -m 644 -t $(DESTDIR)$(man8dir) tofurkey.8
