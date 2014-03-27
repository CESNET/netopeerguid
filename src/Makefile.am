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
	$(APXS) $(LIBS) $(CFLAGS) -c -o $@ $(srcdir)/mod_netconf.c $(srcdir)/notification-server.c

install-exec-local: mod_netconf.so
	if [ "x${httpdmoduledir}" == x ]; then \
	$(APXS) -i -a mod_netconf.la; else \
	{ \
	  mkdir -p "${httpdmoduledir}"; \
	  $(APXS) -i -S LIBEXECDIR="${httpdmoduledir}" -a mod_netconf.la; } \
	fi

webgui-backend$(EXEEXT): mod_netconf.c notification-server.c mod_netconf.h
	$(CC) $(LIBS) $(CFLAGS) -DHTTPD_INDEPENDENT  `apr-1-config  --cflags --cppflags --includes --link-ld` -I/usr/include/httpd  -laprutil-1 -o $@ $(srcdir)/mod_netconf.c $(srcdir)/notification-server.c

clean-local:
	rm -rf .libs *.la *.lo *.slo test-client webgui-backend

distclean-local:
	rm -rf $(RPMDIR)

