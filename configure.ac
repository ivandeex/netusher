dnl -*- Autoconf -*-      vi: set ts=4 sw=4 :
dnl Process this file with autoconf to produce a configure script.
AC_REVISION($Id$)dnl

dnl **** configure.ac for UserWatch ****

AC_PREREQ([2.59])
AC_INIT([userwatch], [0.0.1], [vsemizarov@gmail.com])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR([ChangeLog])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_DEFINE([PACKAGE_COPYRIGHT], ["Copyright (c) 2008, vitki.net"],
          [Define to the project copyright requisites])
AC_DEFINE([PACKAGE_WEBSITE], ["http://vitki.net/v/projects/userwatch"],
          [Define to the project web address])

AM_INIT_AUTOMAKE
AC_CANONICAL_HOST

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AM_PROG_LIBTOOL
AC_PROG_LN_S

AC_C_CONST
AC_TYPE_SIZE_T
AC_FUNC_VPRINTF

AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h])

AC_CHECK_FUNCS([bzero gethostbyname_r])

# GCC 4.x -fvisibility=hidden {
AC_DEFUN([CHECK_GCC_FVISIBILITY],
[
AC_LANG_PUSH(C)
saved_CFLAGS="$CFLAGS"
CFLAGS="$saved_CFLAGS -fvisibility=hidden"
AC_CACHE_CHECK([whether compiler accepts -fvisibility=hidden],
[cv_fvisibility_hidden],
	AC_COMPILE_IFELSE(
		AC_LANG_PROGRAM(
		[],
		[]),
		[cv_fvisibility_hidden=yes],
		[cv_fvisibility_hidden=no]
	)
)
if test "$cv_fvisibility_hidden" = "yes"; then
AC_DEFINE(HAVE_VISIBILITY_HIDDEN, [],
            [True if compiler supports -fvisibility=hidden])
AC_SUBST(GCC_FVISIBILITY_HIDDEN, [-fvisibility=hidden])
fi
CFLAGS="$saved_CFLAGS"
AC_LANG_POP(C)
])dnl
CHECK_GCC_FVISIBILITY()
# }

dnl ================= OpenSSL ===================

AC_CHECKING([for openssl library and headers])
AC_CHECK_HEADER(openssl/ssl.h, [], [AC_MSG_ERROR([openssl headers not found])])
AC_CHECK_LIB(ssl, SSL_CTX_new, [:], [AC_MSG_ERROR([openssl library not found])])

dnl ================= PAM ===================

AC_CHECK_HEADER(security/pam_modules.h,
                [],
                [ AC_MSG_ERROR([PAM headers not found]) ])
AC_CHECK_LIB(pam, pam_start,
             [:],
             [ AC_MSG_ERROR([PAM library not found]) ])

AC_ARG_WITH([pamdir],
            AS_HELP_STRING([--with-pamdir=PATH],
               [Path to the PAM modules directory [[/lib/security]]]),
            [PAM_MODDIR=$withval], [PAM_MODDIR=yes])

AC_MSG_CHECKING(for PAM directory)
test "$PAM_MODDIR" = "no"  && AC_MSG_ERROR([PAM support is required])
test "$PAM_MODDIR" = "yes" && PAM_MODDIR="/lib/security"
test -d "$PAM_MODDIR"      || AC_MSG_ERROR([$PAM_MODDIR not found])
AC_MSG_RESULT([$PAM_MODDIR])

AC_SUBST(PAM_MODDIR)

dnl ================= MySQL ===================

AC_ARG_WITH([mysql],
            AC_HELP_STRING([--with-mysql@<:@=PATH@:>@],
               [PATH to 'mysql_config', MySQL config utility]),
            [MYSQL_CONFIG=$withval], [MYSQL_CONFIG=yes])

test "$MYSQL_CONFIG" = "no"  && AC_MSG_ERROR([mysql support is required])
test "$MYSQL_CONFIG" = "yes" && AC_PATH_PROG(MYSQL_CONFIG, mysql_config)

AC_MSG_CHECKING(for MySQL)
test -z "$MYSQL_CONFIG" && AC_MSG_ERROR([mysql_config is not found])
test -x "$MYSQL_CONFIG" || AC_MSG_ERROR([mysql_config is not executable])
AC_MSG_RESULT($MYSQL_CONFIG)

MYSQL_INCLUDE="`$MYSQL_CONFIG --include`"
old_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$CPPFLAGS $MYSQL_INCLUDE"
AC_CHECK_HEADER(mysql.h,
                [:],
                [ AC_MSG_ERROR([mysql headers not found]) ])
CPPFLAGS=$old_CPPFLAGS

AC_MSG_RESULT(mysql headers: $MYSQL_INCLUDE)
AC_SUBST(MYSQL_INCLUDE)

MYSQL_LIBS="`$MYSQL_CONFIG --libs`"
old_LDFLAGS=$LDFLAGS
LDFLAGS="$LDFLAGS $MYSQL_LIBS"
AC_CHECK_LIB(mysqlclient, mysql_commit,
             [:],
             [ AC_MSG_ERROR([mysql library not found]) ])
LDFLAGS=$old_LDFLAGS

AC_MSG_RESULT(mysql libs: $MYSQL_LIBS)
AC_SUBST(MYSQL_LIBS)

dnl ================= Apache ===================

AC_ARG_WITH([apxs],
            AC_HELP_STRING([--with-apxs@<:@=PATH@:>@],
               [Path to 'apxs', the apache build tool]),
			[APXS=$withval], [APXS=yes])

test "$APXS" = "no"  && AC_MSG_ERROR([Apache support is required])
test "$APXS" = "yes" && AC_PATH_PROG(APXS, apxs)
test -z "$APXS" && APXS="/usr/sbin/apxs"
AC_MSG_CHECKING(for 'apxs' usability)
test -x "$APXS" && $APXS -q CFLAGS >/dev/null 2>&1 || false
test "$?" = 0 || AC_MSG_ERROR(['apxs' is not found or not executable])
AC_MSG_RESULT($APXS)

APXS_INCLUDEDIR=`$APXS -q INCLUDEDIR`
APXS_CFLAGS=`$APXS -q CFLAGS`
APXS_HTTPD=`$APXS -q SBINDIR`/`$APXS -q TARGET`
APXS_LIBEXECDIR=`$APXS -q LIBEXECDIR`
APXS_SYSCONFDIR=`$APXS -q SYSCONFDIR`
APACHE_INCLUDE=-I$APXS_INCLUDEDIR

AC_SUBST(APXS)
AC_SUBST(APXS_INCLUDEDIR)
AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_HTTPD)
AC_SUBST(APXS_LIBEXECDIR)
AC_SUBST(APXS_SYSCONFDIR)
AC_SUBST(APACHE_INCLUDE)

dnl -- maintainer-clean will remove Makefile.in's too
dnl -- this is against common automake rules, for maintainer only.
MAINTAINERCLEANFILES="Makefile.in configure"
AC_SUBST(MAINTAINERCLEANFILES)

AC_OUTPUT

