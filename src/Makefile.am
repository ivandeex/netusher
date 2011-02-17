
## Makefile.am -- Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = autogen.sh

AM_CFLAGS = -Wall

pammoddir = @PAM_MODDIR@

pammod_LTLIBRARIES = pam_userwatch.la

pam_userwatch_la_SOURCES = uw-pam.c
pam_userwatch_la_LDFLAGS = -module -avoid-version -lpam

pam_userwatch_la_CFLAGS = $(GLIB_CFLAGS) -DG_DISABLE_DEPRECATED \
	-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe @GCC_FVISIBILITY_HIDDEN@

DISABLE-install-data-hook:
	( 	cd $(DESTDIR)$(PAM_MODDIR) && \
		$(LN_S) -f pam_userwatch.so pam_userwatch_auth.so && \
		$(LN_S) -f pam_userwatch.so pam_userwatch_session.so \
	)

DISABLE-uninstall-hook:
	rm -f $(DESTDIR)$(PAM_MODDIR)/pam_userwatch_auth.so \
	      $(DESTDIR)$(PAM_MODDIR)/pam_userwatch_session.so

clean-local:
	-rm -f *.slo *.la *~

