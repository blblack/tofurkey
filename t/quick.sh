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
if ! grep -q 'procfs write: 459cc505-4ff0b44e-00836d3d-a429e2c1,de48e41f-ee7b1730-b04fc217-f6f0bd33$' t/testout/log; then
    echo grep check of key contents from t/testout/log failed!
    exit 42
fi

PROCFS_CONTENTS=$(cat t/testout/fake_procfs)
if [ "${PROCFS_CONTENTS}" != "459cc505-4ff0b44e-00836d3d-a429e2c1,de48e41f-ee7b1730-b04fc217-f6f0bd33" ]; then
    echo Contents of fake procfs output are wrong!
    exit 42
fi

echo Test passed!
exit 0
