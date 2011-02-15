
## Makefile.am -- Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = autogen.sh

AM_CFLAGS = -Wall

pammoddir = @PAM_MODDIR@

pammod_LTLIBRARIES = pam_uwatch.la

pam_uwatch_la_SOURCES = uw-pam.c
pam_uwatch_la_LDFLAGS = -module -avoid-version -lpam

pam_uwatch_la_CFLAGS = $(GLIB_CFLAGS) -DG_DISABLE_DEPRECATED \
	-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe @GCC_FVISIBILITY_HIDDEN@

install-data-hook:
	( 	cd $(DESTDIR)$(PAM_MODDIR) && \
		$(LN_S) -f pam_uwatch.so pam_uwatch_auth.so && \
		$(LN_S) -f pam_uwatch.so pam_uwatch_session.so \
	)

uninstall-hook:
	rm -f $(DESTDIR)$(PAM_MODDIR)/pam_uwatch_auth.so \
	      $(DESTDIR)$(PAM_MODDIR)/pam_uwatch_session.so

clean-local:
	-rm -f *.slo *.la *~

