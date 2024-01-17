#!/bin/bash

# Setup
if [[ ! -f ./tofurkey ]] || [[ ! -d t ]]; then
    echo Run this from the repo root after building!
    exit 42
fi
mkdir -p t/testout
touch t/testout/fake_procfs

echo Running slow test, takes at least 17 seconds...

# Execution
: "${TEST_RUNNER:=}"
${TEST_RUNNER} ./tofurkey -i 10 -k t/test.key -P t/testout/fake_procfs -V >t/testout/log 2>&1 &
TOFURKEY_PID=$!

sleep 17
kill -TERM "${TOFURKEY_PID}"
wait "${TOFURKEY_PID}"
TOFURKEY_SIG=$(kill -l $?)
if [[ "${TOFURKEY_SIG}"x = "TERMx" ]]; then
    echo OK: Daemon exited via SIGTERM as expected!
else
    echo FAIL: Daemon did /not/ exit via SIGTERM as expected!
    exit 42
fi

# The above execution used the real unix time, so the key output values aren't
# easily deterministic for testing (unless we have an independent
# implementation of blake2b for the testsuite!)
# However, the /pattern/ of the output is predictable, specifically:
# 1. that a certain minimum count of wakeups should happen in 17 seconds (plus possibly one extra, depending on the start time modulo 5)
# 2. that based on the first-half/second-half indicated in the logs, we should see a pattern of repeating key values something like:
#    second: A, B
#    first: B, A
#    second: B, C
#    first: C, B
#    second: C, D
#    (although we can't gaurantee whether we start on "first" or "second")
# TODO: sort out details for reliability and write something which parses the log for these things
# At least for now, it's useful to have sanitizers+valgrind run on this execution, even without the output testing

echo Test passed!
exit 0
