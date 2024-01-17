#!/bin/sh
if [ ! -d t ] || [ ! -d qa ]; then
   echo "Run this from the repo root!"
   exit 42
fi
set -e
set -x
astyle -q -n --options=.astylerc ./*.c
