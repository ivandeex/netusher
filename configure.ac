dnl -*- Autoconf -*-      vi: set ts=4 sw=4 :
dnl Process this file with autoconf to produce a configure script.
AC_REVISION($Id$)dnl

dnl **** configure.ac for NetUsher ****

AC_PREREQ([2.59])
AC_INIT([netusher], [0.1], [ivandeex@gmail.com])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([Makefile src/Makefile daemons/Makefile webui/Makefile etc/Makefile])

AC_DEFINE([PACKAGE_COPYRIGHT], ["Copyright (c) 2011, ivandeex"],
          [Define to the project copyright requisites])
AC_DEFINE([PACKAGE_WEBSITE], ["https://www.vanko.me/book/page/netusher"],
          [Define to the project web address])

AM_INIT_AUTOMAKE
AC_CANONICAL_HOST

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AM_PROG_LIBTOOL

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
if test "$PAM_MODDIR" = "yes"; then
    dnl -- prefer 64-bit location, if it exists
    PAM_MODDIR="/lib64/security"
    test -d "$PAM_MODDIR" || PAM_MODDIR="/lib/security"
fi
test -d "$PAM_MODDIR" || AC_MSG_ERROR([$PAM_MODDIR not found])
AC_MSG_RESULT([$PAM_MODDIR])

AC_SUBST(PAM_MODDIR)

dnl -- maintainer-clean will remove Makefile.in's too
dnl -- this is against common automake rules, for maintainer only.
MAINTAINERCLEANFILES="Makefile.in configure"
AC_SUBST(MAINTAINERCLEANFILES)

AC_OUTPUT

