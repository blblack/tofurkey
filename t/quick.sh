#!/bin/sh

# Setup
if [ ! -f ./tofurkey ] || [ ! -d t ]; then
    echo Run this from the repo root after building!
    exit 42
fi
mkdir -p t/testout
touch t/testout/fake_procfs

# Execution
: "${TEST_RUNNER:=}"
if ! ${TEST_RUNNER} ./tofurkey -o -k t/test.key -P t/testout/fake_procfs -V -T 1000000 >t/testout/log 2>&1; then
    echo tofurkey exited with failed status $?
    exit 42
fi

# Results checks
if ! grep -q 'procfs write: 82622c1b-b09d71c9-148e70d4-1dab6d02,e6a3d0b6-f85bc3bd-e1e7e044-94299bb3$' t/testout/log; then
    echo grep check of key contents from t/testout/log failed!
    exit 42
fi

PROCFS_CONTENTS=$(cat t/testout/fake_procfs)
if [ "${PROCFS_CONTENTS}" != "82622c1b-b09d71c9-148e70d4-1dab6d02,e6a3d0b6-f85bc3bd-e1e7e044-94299bb3" ]; then
    echo Contents of fake procfs output are wrong!
    exit 42
fi

echo Test passed!
exit 0
