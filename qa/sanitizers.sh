#!/bin/sh
# run from top of repo
if [ ! -d t ] || [ ! -d qa ]; then
   echo "Run this from the root of the source tree!"
   exit 42
fi

# Note this uses gcc-10's sanitizers, this probably won't work with earlier gcc versions or other variants

set -x
set -e
export ASAN_OPTIONS="check_initialization_order=true:detect_invalid_pointer_pairs=10:strict_string_checks=true:detect_stack_use_after_return=true"
CFLAGS="-O1 -fno-omit-frame-pointer -fno-common -fno-sanitize-recover=all -fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fsanitize=bounds -fsanitize=alignment -fsanitize=object-size -fsanitize-address-use-after-scope -fsanitize=pointer-compare -fsanitize=pointer-subtract -fsanitize=signed-integer-overflow" make clean check CC=gcc SLOW_TESTS=1
