CFLAGS=-O3 -Wall -I/usr/local/include -L/usr/local/lib
LDFLAGS=-lwolfssl

.PHONY: examples clean

examples: examples/tls13-client-with-sniffer \
	examples/tcp-client

examples/tls13-client-with-sniffer: examples/tls13-client-with-sniffer.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@.out

examples/tcp-client: examples/tcp-client.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@.out

clean:
	$(RM) examples/*.out
