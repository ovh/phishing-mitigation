# RegEx needs lib pcre (apt-get install libpcre3-dev)
TMC = 1
export TMC
include Makefile.inc

_CC = $(TILERA_ROOT)/bin/tile-cc
_AR = ar
export _CC
export _AR

ofpbase.lib.dir := ./base/lib
ovhcommon.lib.dir := ./common/lib

BINS_DIR = bin
OBJS_DIR = .objs
INSTALL_DIR = /usr/local/bin
CONFIG_DIR = /etc/tilera-phishing
LOG_DIR = /var/log/tilera-phishing
RELOAD_EXE = tilera-phishing-reload.sh

COMMIT_ID = $(shell git rev-parse HEAD)

SRCS = ofp_main.c ofp_netio.c ofp_tcp.c ofp_phish.c\
 ofp_packet_list.c ofp_config.c ofp_logger.c\
 ofp_gc.c ofp_pcap.c ofp_channels.c\
 ofp_packet_helpers.c

OBJS = $(SRCS:%.c=$(OBJS_DIR)/%.o)
BIN = $(BINS_DIR)/tilera-phishing
LIBS = $(ofpbase.lib.dir)/libofpbase.a $(ovhcommon.lib.dir)/libovhcommon.a
DEPS = $(SRCS:%.c=$(OBJS_DIR)/%.o.deps)


ifneq ($(DEBUG),0)
	OPTIM_FLAGS = -O0
else
	OPTIM_FLAGS = -Os
endif

#Do Link Time Optimisation(lto) if not disabled
ifeq ($(NO_LTO),0)
	OPTIM_FLAGS += -flto
endif

CPPFLAGS =
CFLAGS = -std=gnu99 -Wall -Werror -g -I./base -I./common -I. $(OPTIM_FLAGS)

LDFLAGS = -L$(ofpbase.lib.dir) -L$(ovhcommon.lib.dir) -rdynamic $(OPTIM_FLAGS)

LDLIBS = -lpthread -lgxio -ltmc -lofpbase -lovhcommon
#regex lib
ifneq ($(REGEX),0)
	LDLIBS += -lpcre
endif



all: $(BIN)

base_lib:
	cd ./base && $(MAKE) $(MFLAGS)

common_lib:
	cd ./common && $(MAKE) $(MFLAGS)

-include $(DEPS)

$(BIN):: base_lib common_lib

$(BIN):: $(LIBS) $(OBJS)
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJS_DIR)/%.o: %.c
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_CC) $(COMMON_CPPFLAGS) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -MMD -MF $@.deps

install: $(BIN)
	install -m 0755 $(BIN) $(INSTALL_DIR)/tilera-phishing
	install -m 0755 $(RELOAD_EXE) $(INSTALL_DIR)/$(RELOAD_EXE)
	install -m 0755 main.initd /etc/init.d/tilera-phishing
	test -d $(LOG_DIR) || mkdir -p $(LOG_DIR)
	test -d $(CONFIG_DIR) || mkdir $(CONFIG_DIR)
	test -e $(CONFIG_DIR)/main.conf || install conf/main.conf $(CONFIG_DIR)/main.conf
	test -e $(CONFIG_DIR)/ip.conf || install conf/ip.conf $(CONFIG_DIR)/ip.conf
	touch $(CONFIG_DIR)/dump.ips
	test -e $(PCAP_DUMP_DIR) || mkdir $(PCAP_DUMP_DIR)
	echo -e '\033[32mInstall Done!\033[0m'

clean:
	cd ./base && $(MAKE) clean
	cd ./common && $(MAKE) clean

ifneq ($(wildcard ./tests/Makefile),)
	cd ./tests && $(MAKE) clean
endif

ifneq ($(wildcard ./stats-collector/Makefile),)
	cd ./stats-collector && $(MAKE) clean
endif

	rm -rf $(OBJS_DIR)
	rm -rf $(BINS_DIR)

re : clean all

.PHONY: all clean re install tests stats perf base_lib common_lib

tests:
	cd ./tests && $(MAKE) $(MFLAGS)

perf:
	cd ./tests/perf && $(MAKE) $(MFLAGS)

stats:
	cd ./stats-collector && $(MAKE) $(MFLAGS)
