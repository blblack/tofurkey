#!/bin/sh
if [ ! -d t ] || [ ! -d qa ]; then
   echo "Run this from the repo root!"
   exit 42
fi
set -e
set -x
cppcheck --platform=unix64 --std=c11 --enable=all --inconclusive --suppress=missingIncludeSystem --suppress=checkersReport --inline-suppr --max-configs=999 --quiet --error-exitcode=42 -I. .
