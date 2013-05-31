CC = $(CROSS_COMPILE)gcc
prefix ?= /usr/local

socksnatd: socksnatd.o config.o
	$(CC) -o $@ $^ -lpthread

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: socksnatd
	mkdir -p $(DESTDIR)/$(prefix)/bin
	cp -vf socksnatd $(DESTDIR)/$(prefix)/bin/

clean:
	rm -f socksnatd *.o

