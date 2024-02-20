#!/bin/sh

BIN=./tofurkey

# Setup
if [ ! -f "${BIN}" ] || [ ! -d t ]; then
    echo Run this from the repo root after building!
    exit 42
fi
mkdir -p t/testout
touch t/testout/fake_procfs
: "${TEST_RUNNER:=}"

# Execution
if ! ${TEST_RUNNER} "${BIN}" -o -k t/test.key -P t/testout/fake_procfs -V -T 1000000 >t/testout/log 2>&1; then
    echo BASIC: tofurkey exited with failed status $?
    exit 42
fi

# Results checks on the log
if ! grep -q 'procfs write: \[1000000] c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577$' t/testout/log; then
    echo BASIC: grep check of key contents from t/testout/log failed!
    exit 42
fi

# Results checks on the fake procfs output
PROCFS_CONTENTS=$(cat t/testout/fake_procfs)
if [ "${PROCFS_CONTENTS}" != "c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577" ]; then
    echo BASIC: Contents of fake procfs output are wrong!
    exit 42
fi

# Run the same test again, just use -a to pick up the same fixed key as -k
if ! ${TEST_RUNNER} "${BIN}" -o -a t/test.key -P t/testout/fake_procfs -V -T 1000000 >t/testout/log 2>&1; then
    echo AUTOKEY-FIX: tofurkey exited with failed status $?
    exit 42
fi

# Results checks on the log
if ! grep -q 'procfs write: \[1000000] c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577$' t/testout/log; then
    echo AUTOKEY-FIX: grep check of key contents from t/testout/log failed!
    exit 42
fi

# Results checks on the fake procfs output
PROCFS_CONTENTS2=$(cat t/testout/fake_procfs)
if [ "${PROCFS_CONTENTS2}" != "c998252e-8f89667d-31961e08-3897526b,1c9ca1a5-9d295055-f8e3d4df-7107b577" ]; then
    echo AUTOKEY-FIX: Contents of fake procfs output are wrong!
    exit 42
fi

# Test creating a fresh, dynamic autokey
rm -f t/testout/autokey
if ! ${TEST_RUNNER} "${BIN}" -o -a t/testout/autokey -P t/testout/fake_procfs -V -T 1000000 >t/testout/log 2>&1; then
    echo AUTOKEY-DYN1: tofurkey exited with failed status $?
    exit 42
fi

# Copy the procfs generated above and then re-run to see the same output when loading the key that was written above
rm -f t/testout/fake_procfs.prev
cp t/testout/fake_procfs t/testout/fake_procfs.prev
if ! ${TEST_RUNNER} "${BIN}" -o -a t/testout/autokey -P t/testout/fake_procfs -V -T 1000000 >t/testout/log 2>&1; then
    echo AUTOKEY-DYN2: tofurkey exited with failed status $?
    exit 42
fi
if ! cmp t/testout/fake_procfs t/testout/fake_procfs.prev; then
    echo AUTOKEY-DYN2: Procfs output differed between the two autokey runs
    exit 42
fi

echo Quick tests passed!
exit 0
