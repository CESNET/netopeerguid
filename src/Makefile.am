SRCS=mod_netconf.c \
     notification-server.c

HDRS=message_type.h \
     notification_module.h \
     mod_netconf.h

noinst_PROGRAMS=webgui-backend
webgui_backend_SOURCES=mod_netconf.c notification-server.c message_type.h notification_module.h mod_netconf.h

EXTRA_DIST=$(SRCS) $(HDRS)

dist-hook:
	cp $(SRC) $(HDRS) $(distdir)

all: mod_netconf.so webgui-backend

mod_netconf.so: mod_netconf.c notification-server.c
	$(CC) $(CFLAGS) -o $@ $(srcdir)/mod_netconf.c $(srcdir)/notification-server.c $(LIBS)

webgui-backend$(EXEEXT): mod_netconf.c notification-server.c mod_netconf.h
	$(CC) $(CFLAGS) -o $@ $(srcdir)/mod_netconf.c $(srcdir)/notification-server.c $(LIBS)

clean-local:
	rm -rf .libs *.la *.lo *.slo webgui-backend

distclean-local:
	rm -rf $(RPMDIR)

