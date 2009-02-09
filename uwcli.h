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

  Client definitions

*/

#include "config.h"
#include "defaults.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

int uwcli_open(void);
int uwcli_close(void);
int uwcli_put(const char *buf, ...);
int uwcli_get(char *buf, int bufsize);

