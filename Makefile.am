
## Makefile.am -- Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = autogen.sh

AM_CFLAGS = -Wall

# ======== PROGRAMS ========

sbin_PROGRAMS = uwatchd uwcli

uwatchd_SOURCES = uwsrv_main.c uwsrv_ssl.c uwsrv_mysql.c
uwatchd_CPPFLAGS = $(MYSQL_INCLUDE)
uwatchd_LDFLAGS = $(MYSQL_LIBS) -lssl

uwcli_SOURCES = uwcli_main.c uwcli_ssl.c
uwcli_LDFLAGS = -lssl

# ======== PAM ========

pammoddir = @PAM_MODDIR@

pammod_LTLIBRARIES = pam_uwatch.la

pam_uwatch_la_SOURCES = uwcli_pam.c
pam_uwatch_la_LDFLAGS = -module -avoid-version -lssl -lpam

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

# ======== APACHE MODULE ========

noinst_DATA = libmod_uwatch.la
libmod_uwatch_la_SOURCE = httpd_uwatch.c
libmod_uwatch_la_CCFLAG = -DUWATCH_SCAN_PROXY=1
libmod_uwatch_la_LDFLAG = -lssl
apache_modname = uwatch

libmod_uwatch.la: $(libmod_uwatch_la_SOURCE)
	$(APXS) -c -n $(apache_modname) \
		-Wc,$(shell echo $(libmod_uwatch_la_CCFLAG) | tr ' ' ',') \
		-Wl,$(shell echo $(libmod_uwatch_la_LDFLAG) | tr ' ' ',') \
		-o $@ $(libmod_uwatch_la_SOURCE)


install-exec-hook:
	(	mkdir -p $(DESTDIR)$(APXS_LIBEXECDIR) && \
		mkdir -p $(DESTDIR)$(APXS_SYSCONFDIR) && \
		$(APXS) -S LIBEXECDIR=$(DESTDIR)$(APXS_LIBEXECDIR) \
				-S SYSCONFDIR=$(DESTDIR)$(APXS_SYSCONFDIR) \
				-i -n $(apache_modname) libmod_uwatch.la \
	)


clean-local:
	-rm -f *.slo *.la *~

