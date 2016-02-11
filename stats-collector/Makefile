# Prerequiste : 
# rrdtool lib : librrd-dev

CC = gcc

EXE = bin/ofp-stats-collector
CFLAGS = -std=gnu99 -Wall -Werror -g -O2

all: $(EXE)

$(EXE): ofp-stats-collector.c
	@dirname $@ | xargs mkdir -p 2>/dev/null || echo "$@ already exists" >/dev/null
	$(CC) $(CFLAGS) -lrrd -o $@ $<

clean:
	rm -f bin/*

.PHONY: all clean install
