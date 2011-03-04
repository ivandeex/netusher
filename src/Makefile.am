## Makefile.am -- Process this file with automake to produce Makefile.in
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA
#

AUTOMAKE_OPTIONS = gnu

noinst_PROGRAMS = pam_netusher.so

AM_CPPFLAGS = -I$(top_srcdir)
AM_CFLAGS = -Wall -Wno-strict-aliasing -fPIC

pam_mod_dir = @PAM_MODDIR@

pam_netusher_so_SOURCES = nu-pam.c
pam_netusher_so_LDFLAGS = -shared
pam_netusher_so_LDADD = -lpam

pam_netusher_so_CFLAGS = $(GLIB_CFLAGS) -D_REENTRANT $(AM_CFLAGS) -pipe @GCC_FVISIBILITY_HIDDEN@

install-exec-local: install-pam_netusher_so

uninstall-local: uninstall-pam_netusher_so

install-pam_netusher_so: pam_netusher.so
	$(INSTALL_PROGRAM) -D pam_netusher.so $(DESTDIR)$(pam_mod_dir)/pam_netusher.so

uninstall-pam_netusher_so:
	-rm -f $(DESTDIR)$(pam_mod_dir)/pam_netusher.so

clean-local:
	-rm -f *.slo *.la *~

