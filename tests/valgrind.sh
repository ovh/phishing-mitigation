#!/bin/sh
LD_LIBRARY_PATH=../dependencies/cmocka-1.0.1/build/src/ valgrind --db-attach=yes --track-origins=yes --read-var-info=yes --leak-check=full --show-reachable=yes ./bin/tests

