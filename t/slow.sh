#!/bin/bash

BIN=$1
# default to C binary in-tree
if [ "${BIN}x" = "x" ]; then
    BIN=./tofurkey
fi

OUT=./t/testout_slow
FAKE_PROCFS="${OUT}/fake_procfs"
LOG="${OUT}/log"
KEY=t/test.key

# Setup
if [[ ! -f "${BIN}" ]] || [[ ! -d t ]]; then
    echo Run this from the repo root after building!
    exit 42
fi
mkdir -p "${OUT}"
touch "${FAKE_PROCFS}"

echo Running slow test, takes at least 23 seconds...

# Execution
: "${TEST_RUNNER:=}"
${TEST_RUNNER} "${BIN}" -i 10 -k "${KEY}" -P "${FAKE_PROCFS}" -V >"${LOG}" 2>&1 &
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

if ! t/output_checker.py "${KEY}" "${LOG}"; then
    echo FAIL: Output checks failed!
    exit 42
fi
echo Slow test passed!
exit 0
