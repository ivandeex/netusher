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

  User-watch client.

*/

#include <stdio.h>
#include <getopt.h>

#include "uwcli.h"


/*
	command line options
*/
#define CMD_OPTIONS "c:dh"

struct option cmd_options[] = {
	{"help", no_argument, NULL, 'h'},
	{"config", no_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{0, 0, 0, 0}
};

char   *cmd_help =
	"%s - userwatch client\n"
	"Usage: %s [OPTIONS]...\n"
	"  -h / --help              - this help \n"
	"  -d / --debug             - print debugging output \n"
	"\n"
	"(c) vitki.net\n";


/*
	Main routine
*/
int
main (int argc, char **argv)
{
	char buf[UW_BUFSIZE];
	char *	prog = argv[0];
	int		debug = 0;
	int     c;

	for (;;) {
		c = getopt_long(argc, argv, CMD_OPTIONS, cmd_options, NULL);
		if (c == EOF)
			break;
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 0:
			break;
		case 'h':
		default:
			printf(cmd_help, prog, prog);
			exit(1);
		}
	}

	if (uwcli_open() == 0) {
		uwcli_put("HELO");
		uwcli_put("BYE");
		while(uwcli_get(buf, sizeof buf) > 0) {
			fprintf(stdout, "SERVER> %s\n", buf);
			fflush(stdout);
			if (! strcmp(buf, "BYE"))
				break;
		}
		uwcli_close();
	}

	return 0;
}

