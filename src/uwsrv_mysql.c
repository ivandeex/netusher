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

  User-watch server.

*/

#include <mysql.h>

#include "uwsrv.h"

MYSQL mysql_conn, *mysql;


/*
	Main routine
*/
int
mysql_test (void)
{
	MYSQL_RES *result;
	int i, num;
	char query[256];

	mysql = mysql_init(&mysql_conn);
	if (NULL == mysql) {
		printf("mysql_init failed: %s\n", mysql_error(&mysql_conn));
		return -1;
	}

	mysql = mysql_real_connect(&mysql_conn, UW_MYSQL_HOST, UW_MYSQL_USER,
							UW_MYSQL_PASS, NULL, UW_MYSQL_PORT,
							NULL, 0);
	if (NULL == mysql) {
		printf("mysql_real_connect failed: %s\n", mysql_error(&mysql_conn));
		return -1;
	}

	if (mysql_select_db(mysql, UW_MYSQL_DB) != 0) {
		printf("mysql_select_db failed: %s\n", mysql_error(&mysql_conn));
		return -1;
	}

	snprintf(query, sizeof(query)-1,
			"SET CHARACTER SET %s",
			UW_MYSQL_CHARSET);
	if (mysql_query(mysql, query) != 0) {
		printf("mysql set_charset failed: %s\n", mysql_error(&mysql_conn));
		return -1;
	}

	snprintf(query, sizeof(query)-1,
			"SELECT user_id, user_name FROM wiki_user WHERE user_name LIKE '%s'",
			"%m%");
	if (mysql_query(mysql, query) != 0) {
		printf("mysql query failed: %s\n", mysql_error(&mysql_conn));
		return -1;
	}

	result = mysql_store_result(mysql);
	num = NULL == result ? -1 : mysql_num_rows(result);
	printf ("got %d rows from mysql\n", num);
	for (i = 0; i < num; i++) {
		MYSQL_ROW row = mysql_fetch_row(result);
		printf("row %d: '%s' '%s'\n", i, row[0], row[1]);
	}

	if (result) {
		mysql_free_result(result);
	}

	mysql_close(mysql);
	return 0;
}

