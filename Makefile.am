ACLOCAL_AMFLAGS = -I m4


SUBDIRS=src
DIST_SUBDIRS=src

RPMDIR = RPMBUILD

dist-hook:
	find "$(distdir)" -name .gitignore -exec rm {} \;

DISTCHECK_CONFIGURE_FLAGS="--without-systemd"
if HAVE_SYSTEMD
systemddir=@SYSTEMD_UNIT_DIR@
systemd_DATA=nemea-supervisor.service
endif

if MAKE_RPMS

RPMFILENAME=$(PACKAGE_NAME)-$(VERSION)
.PHONY: rpm
rpm:
	rm -rf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	mkdir -p $(RPMDIR)/BUILD/ $(RPMDIR)/SRPMS/ $(RPMDIR)/RPMS/ $(RPMDIR)/SOURCES
	make ${AM_MAKEFLAGS} distdir='$(RPMDIR)/SOURCES/$(RPMFILENAME)' distdir
	find "$(RPMDIR)" -name '*.back' -exec rm -f {} \;
	( cd "$(RPMDIR)/SOURCES/"; tar -z -c -f $(RPMFILENAME)-$(RELEASE).tar.gz $(RPMFILENAME); rm -rf $(RPMFILENAME); )
	$(RPMBUILD) -ba $(PACKAGE_NAME).spec --define "_topdir `pwd`/$(RPMDIR)";

rpm-clean:
	rm -rf $(RPMDIR)
else
endif
