SRCS=netopeerguid.c \
     notification_server.c

HDRS=message_type.h \
     notification_server.h \
     netopeerguid.h

EXTRA_DIST=$(SRCS) $(HDRS)

bin_PROGRAMS=netopeerguid

dist-hook:
	cp $(SRC) $(HDRS) $(distdir)

all: netopeerguid test-client

netopeerguid$(EXEEXT): netopeerguid.c notification_server.c netopeerguid.h
	$(CC) $(CFLAGS) -o $@ $(srcdir)/netopeerguid.c $(srcdir)/notification_server.c $(LIBS)

test-client$(EXEEXT): test-client.c
	$(CC) $(CFLAGS) -o $@ $(srcdir)/test-client.c $(LIBS)

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)/etc/init.d/;
	$(INSTALL_PROGRAM) -m 755 netopeerguid.rc $(DESTDIR)/etc/init.d/
clean-local:
	rm -rf netopeerguid

distclean-local:
	rm -rf $(RPMDIR)

