#!/bin/sh
LD_LIBRARY_PATH=../dependencies/cmocka-1.0.1/build/src/ gdb ./bin/tests --ex "run"