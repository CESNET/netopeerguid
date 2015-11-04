#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([mod_netconf], [1.0.2], [cejkat@cesnet.cz])
AM_INIT_AUTOMAKE([silent-rules])
AM_SILENT_RULES([yes])

USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`
AC_SUBST(USERNAME)
AC_SUBST(USERMAIL)

RELEASE=1
AC_SUBST(RELEASE)

AC_ARG_VAR(SU_USER, [Change UID of process according to username.])
if test "x$SU_USER" == x; then
  SU_USER=""
fi
AC_SUBST([SU_USER])

AC_ARG_VAR(SU_GROUP, [Change GID of process according to groupname.])
if test "x$SU_GROUP" == x; then
  SU_GROUP=""
fi
AC_SUBST([SU_GROUP])

AC_ARG_VAR(CHOWN_USER, [Use chown (user) on socket file.])
if test "x$CHOWN_USER" == x; then
  CHOWN_USER=""
fi
AC_SUBST([CHOWN_USER])

AC_ARG_VAR(CHOWN_GROUP, [Use chown (group) on socket file.])
if test "x$CHOWN_GROUP" == x; then
  CHOWN_GROUP=""
fi
AC_SUBST([CHOWN_GROUP])

# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, [rpmbuild], [rpmbuild], [""])
AC_CHECK_PROG(HTTPD, [httpd], [yes], [""])
AC_PATH_PROGS(APACHECTL, apachectl apache2ctl, no, [$PATH:/usr/sbin])

# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
RPM_RELEASE=1
AC_SUBST(RPM_RELEASE)
AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

# Checks for libraries.
# save clean LIBS and CFLAGS
SAVEDTEMP_LIBS=$LIBS
SAVEDTEMP_CFLAGS=$CFLAGS
PKG_CHECK_MODULES([json], [json])
PKG_CHECK_MODULES([netconf], [libnetconf])
PKG_CHECK_MODULES([xml], [libxml-2.0])
AX_PTHREAD([CC="$PTHREAD_CC"], [AC_MSG_ERROR([pthread not found])])
CFLAGS="-Wall -Wextra $json_CFLAGS $netconf_CFLAGS $xml_CFLAGS $PTHREAD_CFLAGS"
LIBS="$json_LIBS $netconf_LIBS $xml_LIBS $PTHREAD_LIBS"
CPPFLAGS="$xml_CPPFLAGS"

AC_ARG_WITH([notifications],
[AC_HELP_STRING([--without-notifications], [Disable notifications])],
[AS_IF([test "x$with_notifications" == "xno"],[CFLAGS="$CFLAGS"],
[PKG_CHECK_MODULES([websockets], [libwebsockets],
[CFLAGS="$CFLAGS $websockets_CFLAGS -DWITH_NOTIFICATIONS"
LIBS="$LIBS $websockets_LIBS"])])],
[PKG_CHECK_MODULES([websockets], [libwebsockets],
[CFLAGS="$CFLAGS $websockets_CFLAGS -DWITH_NOTIFICATIONS"
LIBS="$LIBS $websockets_LIBS"])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getdelim gettimeofday memset socket strdup strerror])

AC_CONFIG_FILES([Makefile
                config.h
		mod_netconf.spec
		src/Makefile
		])
AC_OUTPUT

echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE $VERSION"
echo "------------------------------------------------------------------------"
echo
echo
echo "Configuration Options Summary:"
echo
echo "Documentation..........: ${build_doc}"
echo
echo "Compilation............: make (or gmake)"
echo "  CC...................: $CC"
echo "  LIBS.................: $LIBS"
echo "  CFLAGS...............: $CFLAGS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo "  python module dir....: $pyplugindir"
echo "  webgui dir...........: $webguidir"
echo "  webgui name..........: $webguiname"
echo "Su user for process:...............: $SU_USER"
echo "Su group for process:..............: $SU_GROUP"
echo "Chown user for sock file:...............: $CHOWN_USER"
echo "Chown group for sock file:..............: $CHOWN_GROUP"
echo

