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

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "uwsrv.h"


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
	"%s - userwatch server\n"
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
	char *	prog = argv[0];
	int		debug = 0;
	int     c, pid, logfd, nulfd;
	FILE*	pidfile;

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

	//mysql_test();

	if (debug) {
		return ssl_server();
	}

	pid = 0;
	pidfile = fopen(UW_PIDFILE, "r");
	if (pidfile != NULL) {
		fscanf(pidfile, " %d", &pid);
		fclose(pidfile);
		if (kill(pid, 0) < 0)
			pid = 0;
	}
	if (pid != 0) {
		fprintf(stderr, "another uwd is running (pid %d)\n", pid);
		return 1;
	}

	pidfile = fopen(UW_PIDFILE, "w");
	if (NULL == pidfile) {
		fprintf(stderr, "cannot write to pidfile %s\n", UW_PIDFILE);
		return 1;
	}

	logfd = open(UW_LOGFILE, O_WRONLY|O_APPEND|O_CREAT|O_TRUNC, 0666);
	if (logfd < 0) {
		fprintf(stderr, "cannot write to logfile %s\n", UW_LOGFILE);
		return 1;
	}

	nulfd = open("/dev/null", O_RDONLY);
	if (nulfd < 0) {
		fprintf(stderr, "cannot open /dev/null");
		return 1;
	}

	pid = fork();
	if (pid == -1) {
		perror("fork() failed");
		return 1;
	}

	if (pid != 0) {
		close(logfd);
		close(nulfd);
		fprintf(pidfile, "%d\n", pid);
		fclose(pidfile);
		return 0;
	}

	dup2(nulfd, 0);
	dup2(logfd, 1);
	dup2(logfd, 2);
	close(nulfd);
	close(logfd);
	setsid();

	printf("starting server\n");
	ssl_server();
	return 0;
}


int
handle_request(const char *buf)
{
	fprintf(stdout, "CLIENT> %s\n", buf);
	fflush(stdout);
	ssl_put("OK");

	if (strncmp(buf, "BYE", 3) == 0) {
		ssl_put("BYE");
		return 1;
	}

	return 0;
}



