#!/bin/bash

BIN=./tofurkey

# Setup
if [[ ! -f "${BIN}" ]] || [[ ! -d t ]]; then
    echo Run this from the repo root after building!
    exit 42
fi
mkdir -p t/testout
touch t/testout/fake_procfs

echo Running slow test, takes at least 23 seconds...

# Execution
: "${TEST_RUNNER:=}"
${TEST_RUNNER} "${BIN}" -i 10 -k t/test.key -P t/testout/fake_procfs -V >t/testout/log 2>&1 &
TOFURKEY_PID=$!

sleep 23
kill -TERM "${TOFURKEY_PID}"
wait "${TOFURKEY_PID}"
TOFURKEY_SIG=$(kill -l $?)
if [[ "${TOFURKEY_SIG}"x = "TERMx" ]]; then
    echo OK: Daemon exited via SIGTERM as expected!
else
    echo FAIL: Daemon did /not/ exit via SIGTERM as expected!
    exit 42
fi

if ! t/output_checker.py; then
    echo FAIL: Output checks failed!
    exit 42
fi
echo Slow test passed!
exit 0
