CC = $(CROSS_COMPILE)gcc
CFLAGS =

rawtcp-se: rawtcp.o
	$(CC) -o $@ $^ -lpthread

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: rawtcp-se
	mkdir -p /usr/local/bin
	cp -vf rawtcp-se /usr/local/bin/

clean:
	rm -f rawtcp-se *.o

