# To install cmocka go to ../dependencies/cmocka-1.0.1/build and run :
# cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
# make

# RegEx needs lib pcre (apt-get install libpcre3-dev)
TMC = 0
DEBUG ?= 1
export -e TMC
export -e DEBUG
include ../../Makefile.inc

_CC = $(CC)
_AR ?= $(AR)
export -e _CC
export -e _AR


ofpbase.lib.dir := ../../base/lib
ovhcommon.lib.dir := ../../common/lib
cmocka.dir := ../../dependencies/cmocka-1.0.1
cmocka.build.dir := $(cmocka.dir)/build
cmocka.lib.dir := $(cmocka.build.dir)/src

BINS_DIR = bin
COMMIT_ID = $(shell git rev-parse HEAD)

SRCS = test_socket_server.c

OBJS_DIR = .objs/obj
OBJS = $(SRCS:%.c=$(OBJS_DIR)/%.o)
BIN = $(BINS_DIR)/socket_server
LIBS = $(ofpbase.lib.dir)/libofpbase.a $(ovhcommon.lib.dir)/libovhcommon.a

CPPFLAGS =

CFLAGS = -std=gnu99 -Wall -Werror -g -O0 -I. -I../../base -I../../common -I../..

LDFLAGS = -L$(ofpbase.lib.dir) -L$(ovhcommon.lib.dir) -rdynamic
#-Wl,--verbose
LDLIBS = -lpthread -lm -lofpbase -lovhcommon

ifneq ($(REGEX),0)
	LDLIBS += -lpcre
endif

LD_LIBRARY_PATH := $(cmocka.lib.dir)

#see https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html#index-fsanitize_003daddress-666
ifneq ($(GCC_SANITIZE),0)
LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(LIB_PATH)
LDFLAGS += -L$(LIB_PATH) $(OPT)
endif


all: $(BIN)

run: $(BIN)
	@LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) $(BIN)

debug: $(BIN)
	@LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) gdb $(BIN) --ex "run"

valgrind: $(BIN)
	@LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) valgrind --track-origins=yes --error-exitcode=1 --read-var-info=yes --leak-check=full --show-reachable=yes $(BIN)

base_lib:
	cd ../../base && $(MAKE) $(MFLAGS)

common_lib:
	cd ../../common && $(MAKE) $(MFLAGS)

$(BIN):: base_lib common_lib

$(BIN):: $(LIBS) $(OBJS)
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJS_DIR)/%.o: %.c
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_CC) $(COMMON_CPPFLAGS) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	cd ../../base && $(MAKE) clean
	cd ../../common && $(MAKE) clean
	rm -f $(OBJS)
	rm -f $(BIN)

re : clean all

.PHONY: all clean base_lib common_lib
