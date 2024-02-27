#!/bin/bash

# Support initial "-s" arg to run slow tests
if [[ "${1}x" = "-sx" ]]; then
    SLOW=1
    shift
else
    SLOW=0
fi

# default to C binary in-tree, override via $1 for zig cases
BIN=$1
if [[ "${BIN}x" = "x" ]]; then
    BIN=./tofurkey
fi

OUT=./t/testout
FAKE_PROCFS="${OUT}/fake_procfs"
LOG="${OUT}/log"
AUTOKEY="${OUT}/autokey"
KEY=t/test.key

# Setup
if [[ ! -f "${BIN}" ]] || [[ ! -d t ]]; then
    echo Run this from the repo root after building!
    exit 42
fi
mkdir -p "${OUT}"
touch "${FAKE_PROCFS}"
: "${TEST_RUNNER:=}"

# Execution
if ! ${TEST_RUNNER} "${BIN}" -o -k "${KEY}" -P "${FAKE_PROCFS}" -V -T 1000000 >"${LOG}" 2>&1; then
    echo BASIC: tofurkey exited with failed status $?
    exit 42
fi

# Results checks on the log
if ! grep -q 'procfs write: \[1000000] c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577$' "${LOG}"; then
    echo BASIC: grep check of key contents from "${LOG}" failed!
    exit 42
fi

# Results checks on the fake procfs output
IFS= read -r -d '' procfs_contents <"${FAKE_PROCFS}"

if [[ "${procfs_contents}" != "c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577" ]]; then
    echo BASIC: Contents of fake procfs output are wrong!
    exit 42
fi

# Run the same test again, just use -a to pick up the same fixed key as -k
if ! ${TEST_RUNNER} "${BIN}" -o -a "${KEY}" -P "${FAKE_PROCFS}" -V -T 1000000 >"${LOG}" 2>&1; then
    echo AUTOKEY-FIX: tofurkey exited with failed status $?
    exit 42
fi

# Results checks on the log
if ! grep -q 'procfs write: \[1000000] c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577$' "${LOG}"; then
    echo AUTOKEY-FIX: grep check of key contents from "${LOG}" failed!
    exit 42
fi

# Results checks on the fake procfs output
IFS= read -r -d '' procfs_contents2 <"${FAKE_PROCFS}"
if [[ "${procfs_contents2}" != "c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577" ]]; then
    echo AUTOKEY-FIX: Contents of fake procfs output are wrong!
    exit 42
fi

# Test creating a fresh, dynamic autokey
rm -f "${AUTOKEY}"
if ! ${TEST_RUNNER} "${BIN}" -o -a "${AUTOKEY}" -P "${FAKE_PROCFS}" -V -T 1000000 >"${LOG}" 2>&1; then
    echo AUTOKEY-DYN1: tofurkey exited with failed status $?
    exit 42
fi

# Copy the procfs generated above and then re-run to see the same output when loading the key that was written above
rm -f "${FAKE_PROCFS}.prev"
cp "${FAKE_PROCFS}" "${FAKE_PROCFS}.prev"
if ! ${TEST_RUNNER} "${BIN}" -o -a "${AUTOKEY}" -P "${FAKE_PROCFS}" -V -T 1000000 >"${LOG}" 2>&1; then
    echo AUTOKEY-DYN2: tofurkey exited with failed status $?
    exit 42
fi
if ! cmp "${FAKE_PROCFS}" "${FAKE_PROCFS}.prev"; then
    echo AUTOKEY-DYN2: Procfs output differed between the two autokey runs
    exit 42
fi

echo Quick tests passed!
if [[ ${SLOW} -eq 0 ]]; then exit 0; fi
echo Running slow test, takes at least 23 seconds...

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
