CC = $(CROSS_COMPILE)gcc

socksnatd: socksnatd.o
	$(CC) -o $@ $^ -lpthread

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: socksnatd
	mkdir -p /usr/local/bin
	cp -vf socksnatd /usr/local/bin/

clean:
	rm -f socksnatd *.o

