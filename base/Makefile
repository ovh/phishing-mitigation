include ../Makefile.inc

_CC ?= $(TILERA_ROOT)/bin/tile-cc
_AR ?= ar

LIBS_DIR = lib
OBJS_DIR = .objs
COMMIT_ID = $(shell git rev-parse HEAD)

SRCS = \
 ofp_packet_stats.c\
 ofp_http.c\
 ofp_init.c\
 ofp_workers.c\
 ofp_config_ip.c\
 ofp_URI_list.c\
 ofp_errors.c\
 ofp_phish_target_host.c\
 ofp_phish_target_ip.c\
 ofp_phish_target_host_ht.c\
 ofp_socket.c\
 ofp_phish_desc.c\
 ofp_phish_desc_ht.c\
 ofp_socket_message_cb.c\
 ofp_event_http_match.c\
 ofp_phish_target_ip_ht.c\

OBJS = $(SRCS:%.c=$(OBJS_DIR)/%.o)
LIB = $(LIBS_DIR)/libofpbase.a
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
CFLAGS = -std=gnu99 -Wall -Werror -g -I.. -I../common -I. $(OPTIM_FLAGS)

all: $(LIB)

$(LIB): $(OBJS)
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_AR) -cvr $@ $^

-include $(DEPS)

$(OBJS_DIR)/%.o: %.c
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(_CC) $(COMMON_CPPFLAGS) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -MMD -MF $@.deps

clean:
	rm -rf $(OBJS_DIR)
	rm -rf $(LIBS_DIR)

re : clean all

.PHONY: all clean re install tests
