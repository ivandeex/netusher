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

EXTRA_DIST = nginx.d/nginx-netusher.conf httpd.d/apache-netusher.conf

initddir = $(sysconfdir)/rc.d/init.d

dist_initd_SCRIPTS = \
	init.d/nu-client init.d/nu-server

nobase_dist_sysconf_DATA = \
	netusher/nu-client.conf-example netusher/nu-server.conf-example \
	netusher/gmirror.conf-example


