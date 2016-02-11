# To install cmocka go to ../dependencies/cmocka-1.0.1/build and run :
# cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
# make

# RegEx needs lib pcre (apt-get install libpcre3-dev)
TMC = 0
DEBUG = 5
HASH_DEBUG = 1
export -e TMC
export -e DEBUG
export -e HASH_DEBUG

include ../Makefile.inc

_CC = $(CC)
_AR ?= $(AR)
export -e _CC
export -e _AR

cmocka.dir := ../dependencies/cmocka-1.0.1
cmocka.build.dir := $(cmocka.dir)/build
cmocka.lib.dir := $(cmocka.build.dir)/src
cmocka.include.dir := $(cmocka.dir)/include

ofpbase.lib.dir := ../base/lib
ovhcommon.lib.dir := ../common/lib


BINS_DIR = bin
COMMIT_ID = $(shell git rev-parse HEAD)

SRCS = main.c test_data.c\
	ofp_tools_test.c\
	ofp_URI_list_test.c\
	ofp_http_test.c\
	ofp_regex_test.c\
	ofp_config_ip_test.c\
	ofp_socket_test.c\
	ofp_phish_target_host_ht_test.c\
	ofp_phish_target_ip_ht_test.c\
	ofp_phish_desc_ht_test.c\
	ofp_event_queue_test.c\

MAIN_OBJS_DIR = .objs
OBJS_DIR = $(MAIN_OBJS_DIR)/obj
OBJS = $(SRCS:%.c=$(OBJS_DIR)/%.o)
BIN = $(BINS_DIR)/tests
LIBS = $(ofpbase.lib.dir)/libofpbase.a $(ovhcommon.lib.dir)/libovhcommon.a
DEPS = $(SRCS:%.c=$(OBJS_DIR)/%.o.deps)

CPPFLAGS = -DUNIT_TEST=1
CFLAGS = -std=gnu99 -Wall -Werror -g -O0 -I. -I../base -I../common -I.. -I$(cmocka.include.dir)

#WRAP_FLAGS = -Wl,--wrap=malloc -Wl,--wrap=realloc -Wl,--wrap=calloc -Wl,--wrap=free
LDFLAGS := -L$(cmocka.lib.dir) -L$(ofpbase.lib.dir) -L$(ovhcommon.lib.dir) -rdynamic $(WRAP_FLAGS)
#-Wl,--verbose
LDLIBS = -lpthread -lcmocka -lm -lofpbase -lovhcommon

LD_LIBRARY_PATH := $(cmocka.lib.dir)

ifneq ($(REGEX),0)
	LDLIBS += -lpcre
endif

#see https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html#index-fsanitize_003daddress-666
ifneq ($(GCC_SANITIZE),0)
LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(LIB_PATH)
LDFLAGS += -L$(LIB_PATH) $(OPT)
endif

all: run valgrind

run: $(BIN)
	@LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) $(BIN)
	@echo -e '======================='
	@echo -e '\033[32m GREEN BAR!\033[0m'
	@echo -e '======================='

valgrind: $(BIN)
	@LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) valgrind --track-origins=yes --error-exitcode=1 --read-var-info=yes --leak-check=full --show-reachable=yes $(BIN)
	@echo -e '======================='
	@echo -e '\033[32m GREEN BAR!\033[0m'
	@echo -e '======================='

base_lib:
	cd ../base && $(MAKE) $(MFLAGS)

common_lib:
	cd ../common && $(MAKE) $(MFLAGS)

-include $(DEPS)

$(BIN):: base_lib common_lib

$(BIN):: $(LIBS) $(OBJS)
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJS_DIR)/%.o: %.c
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_CC) $(COMMON_CPPFLAGS) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -MMD -MF $@.deps

clean:
ifneq ($(wildcard ./perf/Makefile),)
	cd ./perf && $(MAKE) clean
endif

	cd ../base && $(MAKE) clean
	cd ../common && $(MAKE) clean
	rm -rf $(MAIN_OBJS_DIR)
	rm -rf $(BINS_DIR)

perf:
	cd ./perf && $(MAKE) $(MFLAGS)

re : clean all

.PHONY: all clean perf base_lib common_lib run valgrind
