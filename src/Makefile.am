ARCSID = @ARCSID@
RCSID = @RCSID@

SRCS=mod_netconf.c \
     notification-server.c \
     test-client.c

HDRS=message_type.h \
     notification_module.h \
     mod_netconf.h

all: module client webgui-backend

module: mod_netconf.c
	$(APXS) $(LIBS) $(ARCSID) $(CFLAGS) -c mod_netconf.c notification-server.c

client: test-client.c
	gcc $(RCSID) -std=gnu99 -Wall -g -ljson -I/usr/include/json test-client.c -o test-client

notification-test: notification-server.c
	gcc $(RCSID) -std=gnu99 -Wall -g -lwebsockets -DTEST_NOTIFICATION_SERVER notification-server.c -o notification-test

install-exec-local: module
	$(APXS) -i -a mod_netconf.la

install-data-local: $(TARGETS)
	[ -d $(DESTDIR)/etc/httpd/modules ] || \
		(mkdir -p $(DESTDIR)/$(libdir)/httpd/modules; chmod 755 $(DESTDIR)/$(libdir)/httpd/modules)
	[ -d $(DESTDIR)/$(sysconfdir)/httpd/conf.d/ ] || \
		mkdir -p $(DESTDIR)/$(sysconfdir)/httpd/conf.d/; chmod 755 $(DESTDIR)/$(sysconfdir)/httpd/conf.d/;
	cp mod_netconf.conf $(DESTDIR)/$(sysconfdir)/httpd/conf.d/
#install-exec-local: $(TARGETS)
#	$(APXS) -i $(NAME).la

clean-local:
	rm -rf .libs *.la *.lo *.slo test-client webgui-backend

#.PHONY: tarball
#tarball: $(SRCS) $(HEADERS)
#	@rm -rf $(NAME)-$(VERSION);
#	@mkdir $(NAME)-$(VERSION);
#	for i in $(SRCS) $(HDRS) mod_netconf.conf README configure.in configure \
#	    Makefile.in VERSION $(NAME).spec.in install-sh; do \
#	    [ -d $(NAME)-$(VERSION)/$$(dirname $$i) ] || (mkdir -p $(NAME)-$(VERSION)/$$(dirname $$i)); \
#		cp $$i $(NAME)-$(VERSION)/$$i; \
#	done;
#	@rm -rf $(RPMDIR)/SOURCES/; \
#	mkdir -p $(RPMDIR)/SOURCES/; \
#	tar -c -z -f $(RPMDIR)/SOURCES/$(NAME)-$(VERSION)-$(RELEASE).tar.gz \
#	    $(NAME)-$(VERSION); \
#	rm -rf $(NAME)-$(VERSION);
#
#.PHONY: rpm
#rpm: tarball
#	mkdir -p $(RPMDIR)/BUILD $(RPMDIR)/RPMS $(RPMDIR)/SRPMS
#	$(RPMBUILD) -ba $(PKGNAME).spec \
#	--define "_topdir `pwd`/$(RPMDIR)";
#
#.PHONY: distclean
#distclean:
#	rm -rf $(RPMDIR)

webgui-backend: mod_netconf.c notification-server.c mod_netconf.h
	gcc -Wall -g @SAVED_CFLAGS@ -DHTTPD_INDEPENDENT  $(RCSID) `apr-1-config  --cflags --cppflags --includes --link-ld` -I/usr/include/httpd @SAVED_LIBS@ -laprutil-1 -o $@ mod_netconf.c notification-server.c

