NAME=mod_netconf
SOURCES=$(NAME).c

APXS=/usr/sbin/apxs2

CFLAGS=-I/usr/include/libxml2 
LIBS=-lnetconf -lxml2 -lz -lm 

all: $(SOURCES)
	$(APXS) $(CPPFLAGS) $(CFLAGS) $(LIBS) -c $(SOURCES)

install: $(NAME).la
	$(APXS) -i $(NAME).la

clean:
	rm -rf .libs *.la *.lo *.slo

