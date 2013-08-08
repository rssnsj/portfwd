CC = $(CROSS_COMPILE)gcc
CFLAGS ?= -g
LDFLAGS ?= 
prefix ?= /usr/local

all: socksnatd libsehijack.so

socksnatd: socksnatd.o config.o ipv4_rules.o
	$(CC) -o $@ $^ $(LDFLAGS) -levent

libsehijack.so: libsehijack.c
	$(CC) -Wall -fPIC -nostdlib -shared -D_GNU_SOURCE -ldl -o $@ $<

%.o: %.c config.h ipv4_rules.h utils.h
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: all
	mkdir -p $(DESTDIR)$(prefix)/bin
	mkdir -p $(DESTDIR)$(prefix)/lib
	cp -vf socksnatd $(DESTDIR)$(prefix)/bin/
	cp -vf libsehijack.so $(DESTDIR)$(prefix)/lib/

clean:
	rm -f socksnatd *.o *.so

