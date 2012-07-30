NAME=mod_netconf

APXS=/usr/sbin/apxs2

CFLAGS=-I/usr/include/json
LIBS=-lnetconf -ljson 

all: module client

module: mod_netconf.c
	$(APXS) $(CPPFLAGS) $(CFLAGS) $(LIBS) -c mod_netconf.c

client: test-client.c
	gcc -std=gnu99 -Wall -g -ljson -I/usr/include/json test-client.c -o test-client

install: $(NAME).la
	$(APXS) -i $(NAME).la

clean:
	rm -rf .libs *.la *.lo *.slo test-client

