#!/bin/sh
if [ ! -d t ] || [ ! -d qa ]; then
   echo "Run this from the repo root!"
   exit 42
fi
set -x
set -e
CFLAGS="-O0 -g" make clean all
TEST_RUNNER="valgrind --error-exitcode=99 --leak-check=full" make check SLOW_TESTS=1
set +e
set +x
if grep "ERROR SUM" t/testout/log | grep -v ' 0 errors'; then
    echo "Valgrind found issues, see t/testout/log"
    exit 42
else
    echo "Valgrind OK"
    exit 0
fi
