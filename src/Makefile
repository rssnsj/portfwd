CC ?= $(CROSS_COMPILE)gcc
PREFIX ?= /usr/local
# CFLAGS += -g

ifeq ($(shell uname), Linux)
#LDFLAGS += -levent
else
HEADERS += no-epoll.h
endif

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

