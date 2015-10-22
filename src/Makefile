CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -g
PREFIX ?= /usr/local
HEADERS := ps_epoll.h

all: tcpfwd udpfwd

tcpfwd: tcpfwd.o
	$(CC) -o $@ $^ $(LDFLAGS)

udpfwd: udpfwd.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: all
	mkdir -p $(PREFIX)/bin
	cp -vf tcpfwd udpfwd $(PREFIX)/bin/

clean:
	rm -f tcpfwd udpfwd *.o

