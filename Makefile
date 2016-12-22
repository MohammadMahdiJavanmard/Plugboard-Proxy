
all: pbproxy.c
	gcc pbproxy.c -w -lpthread -lcrypto -lssl -o pbproxy
clean:
	$(RM) pbproxy
