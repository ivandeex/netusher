/* -*-c++-*-  vi: set ts=4 sw=4 :

  (C) Copyright 2008, vitki.net. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

  $Date$
  $Revision$
  $Source$

  Server definitions

*/

#if !defined(UW_NO_CONFIG_H)
#include "config.h"
#endif

#include "defaults.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

int ssl_startup(void);
int ssl_server(void);
int ssl_child(int connfd);
int ssl_child_open(int connfd);
int ssl_child_close(void);
int ssl_put(const char *fmt, ...);
int ssl_get(char *buf, int bufsize);

int mysql_test(void);
int handle_request(const char *buf);


