#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([netopeerguid], [1.0.2], [mvasko@cesnet.cz])
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

AC_DEFINE_DIR(absbindir, [bindir], [Path to binaries])

# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, [rpmbuild], [rpmbuild], [""])

# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
RPM_RELEASE=1
AC_SUBST(RPM_RELEASE)
AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

# Checks for libraries.
# save clean LIBS and CFLAGS
SAVEDTEMP_LIBS=$LIBS
SAVEDTEMP_CFLAGS=$CFLAGS
PKG_CHECK_MODULES([json], [json-c])
PKG_CHECK_MODULES([netconf2], [libnetconf2])
PKG_CHECK_MODULES([yang], [libyang])
AX_PTHREAD([CC="$PTHREAD_CC"], [AC_MSG_ERROR([pthread not found])])
CFLAGS="-Wall -Wextra $json_CFLAGS $netconf2_CFLAGS $yang_FLAGS $PTHREAD_CFLAGS"
LIBS="$json_LIBS $netconf2_LIBS $yang_LIBS $PTHREAD_LIBS"

AC_ARG_WITH([notifications],
    [AC_HELP_STRING([--without-notifications], [Disable notifications])],
    [AS_IF([test "x$with_notifications" == "xno"],[CFLAGS="$CFLAGS"],
        [PKG_CHECK_MODULES([websockets], [libwebsockets],
        [CFLAGS="$CFLAGS $websockets_CFLAGS -DWITH_NOTIFICATIONS" LIBS="$LIBS $websockets_LIBS"])])],
    [PKG_CHECK_MODULES([websockets], [libwebsockets],
        [CFLAGS="$CFLAGS $websockets_CFLAGS -DWITH_NOTIFICATIONS" LIBS="$LIBS $websockets_LIBS"])]
)

AC_ARG_WITH([cert-path],
    AC_HELP_STRING([--with-cert-path], [Set notification server certificate]),
    CERT_PATH="$withval",
    [AS_IF([test "x$with_notifications" == "xno"], [], [AC_MSG_ERROR([Certificate path must be set.])])]
)
AC_SUBST([CERT_PATH])

AC_ARG_WITH([private-key-path],
    AC_HELP_STRING([--with-private-key-path], [Set notification server private key]),
    PRIVKEY_PATH="$withval",
    [AS_IF([test "x$with_notifications" == "xno"], [], [AC_MSG_ERROR([Private key path must be set.])])]
)
AC_SUBST([PRIVKEY_PATH])

AC_ARG_ENABLE([debug],
    AC_HELP_STRING([--enable-debug],[Compile with debug options]),
    CFLAGS="$CFLAGS -g -O0 -DDBG"
    CONFIGURE_PARAMS="--enable-debug $CONFIGURE_PARAMS",
    CFLAGS="$CFLAGS -O3"
)

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

# allow to skip systemd, enabled by default
AC_ARG_WITH([systemd],
        AC_HELP_STRING([--without-systemd], [Disable checking and usage of systemd]),
        [if test "$withval" = "no"; then
                withsystemd="no"
        else
                withsystemd="yes"
        fi], [withsystemd="yes"])

if test "x$withsystemd" = "xyes"; then
        PKG_CHECK_MODULES([systemd], [systemd], [
        SYSTEMD_UNIT_DIR=$(pkg-config --variable=systemdsystemunitdir systemd)
        SYSTEMD_SERVICE_FILE="$SYSTEMD_UNIT_DIR/netopeerguid.service"
        AC_SUBST(SYSTEMD_SERVICE_FILE)
        AC_SUBST(SYSTEMD_UNIT_DIR)
        AM_CONDITIONAL([HAVE_SYSTEMD], [true])
        ], [AM_CONDITIONAL([HAVE_SYSTEMD], [false])])
else
        # disabled systemd
        AM_CONDITIONAL([HAVE_SYSTEMD], [false])
fi


AC_CONFIG_FILES([Makefile
                config.h
		netopeerguid.spec
		netopeerguid.service
		src/netopeerguid.rc
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
echo "Su user for process:...............: $SU_USER"
echo "Su group for process:..............: $SU_GROUP"
echo "Chown user for sock file:...............: $CHOWN_USER"
echo "Chown group for sock file:..............: $CHOWN_GROUP"
echo "Notification server certificate:........: $CERT_PATH"
echo "Notification server private key:........: $PRIVKEY_PATH"
echo

