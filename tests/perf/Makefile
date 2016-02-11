# To install cmocka go to ../dependencies/cmocka-1.0.1/build and run :
# cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
# make

# RegEx needs lib pcre (apt-get install libpcre3-dev)
TMC = 0
DEBUG = 0
export -e TMC
export -e DEBUG
include ../../Makefile.inc

_CC = cc
export -e _CC

ofpbase.lib.dir := ../../base/lib
ovhcommon.lib.dir := ../../common/lib

BINS_DIR = bin
COMMIT_ID = $(shell git rev-parse HEAD)

SRCS = main.c ofp_http_perf.c

OBJS_DIR = .objs/obj
OBJS = $(SRCS:%.c=$(OBJS_DIR)/%.o)
BIN = $(BINS_DIR)/perf
LIBS = $(ofpbase.lib.dir)/libofpbase.a $(ovhcommon.lib.dir)/libovhcommon.a

CPPFLAGS =

CFLAGS = -std=gnu99 -Wall -Werror -g -O0 -I. -I../../base -I../../common -I../..

LDFLAGS = -L$(ofpbase.lib.dir) -L$(ovhcommon.lib.dir) -rdynamic
#-Wl,--verbose
LDLIBS = -lpthread -lm -lofpbase -lovhcommon

ifneq ($(REGEX),0)
	LDLIBS += -lpcre
endif


all: perf

perf: $(BIN)
	$(BIN)

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
