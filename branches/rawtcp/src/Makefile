CC = $(CROSS_COMPILE)gcc
CFLAGS = 

rawtcp: rawtcp.o
	$(CC) -o $@ $^ -levent

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: rawtcp
	mkdir -p /usr/local/bin
	cp -vf rawtcp /usr/local/bin/

clean:
	rm -f rawtcp *.o

