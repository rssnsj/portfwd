CC = $(CROSS_COMPILE)gcc
CFLAGS = -g

all: tcpfwd udpfwd

tcpfwd: tcpfwd.o
	$(CC) -o $@ $^ $(LDFLAGS) -levent

udpfwd: udpfwd.o
	$(CC) -o $@ $^ $(LDFLAGS) -levent

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: tcpfwd
	mkdir -p /usr/local/bin
	cp -vf tcpfwd /usr/local/bin/

clean:
	rm -f tcpfwd udpfwd *.o

