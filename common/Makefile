$(info building common lib)
$(info $(_CC))

include ../Makefile.inc

_CC ?= $(TILERA_ROOT)/bin/tile-cc
_AR ?= ar


LIBS_DIR = lib
OBJS_DIR = .objs
COMMIT_ID = $(shell git rev-parse HEAD)

SRCS = \
ovh_cpu.c\
ovh_log.c\
ovh_regex.c\
ovh_time.c\
ovh_tmc.c\
ovh_tools.c\


OBJS = $(SRCS:%.c=$(OBJS_DIR)/%.o)
LIB = $(LIBS_DIR)/libovhcommon.a
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
CFLAGS = -std=gnu99 -Wall -Werror -g -I.. -I. $(OPTIM_FLAGS)

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

.PHONY: all clean
