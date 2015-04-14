CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -g
PREFIX ?= /usr/local

all: tcpfwd udpfwd

tcpfwd: tcpfwd.o
	$(CC) -o $@ $^ $(LDFLAGS) -levent

udpfwd: udpfwd.o
	$(CC) -o $@ $^ $(LDFLAGS) -levent

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: all
	mkdir -p $(PREFIX)/bin
	cp -vf tcpfwd udpfwd $(PREFIX)/bin/

clean:
	rm -f tcpfwd udpfwd *.o

