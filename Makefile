CPPFLAGS ?= -D_GNU_SOURCE
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wconversion -Warith-conversion -Wshadow -Warray-bounds=2 -Wcast-align=strict -Wcast-qual -Werror=vla -Wfloat-equal -Wstrict-overflow=5 -Wstrict-aliasing
LDFLAGS ?=
LDLIBS ?= -lsodium -lev

DESTDIR ?= /
prefix ?= /usr
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin

.PHONY: all clean distclean check test qa install
all: tofurkey
tofurkey: tofurkey.c
clean:
	$(RM) tofurkey
distclean: clean
check: tofurkey
	t/quick.sh
	@if [ "$(SLOW_TESTS)"x != x ]; then t/slow.sh; fi
test: check
qa: tofurkey
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
install: tofurkey
	install -D -s -m 755 -t $(DESTDIR)$(bindir) tofurkey
