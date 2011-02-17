/* -*-c++-*-  vi: set ts=4 sw=4 :

  (C) Copyright 2011, vitki.net. All rights reserved.

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

  $Id$

  UserWatch PAM module.

*/

#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <assert.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "config.h"

#ifdef HAVE_VISIBILITY_HIDDEN
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#else
#define EXPORT_SYMBOL
#endif

#define UW_DEBUG	1
#define UW_ERROR	0

#define UW_CONFIG_FILE 	"/etc/userwatch/uw-client.conf"
#define UW_SOCKET_PATH	"/var/run/userwatch/uw-client.sock"
#define UW_DATA_NAME	"pam_userwatch_data"
#define UW_MAGIC		0x5A61C
#define UW_CFG_LINE_MAX	256
#define UW_SOCK_BUF_MAX	128

static void uw_cleanup (pam_handle_t *, void *, int);

typedef struct {
	int			magic;
	int			debug;
	int			use_auth_tok;
	char *		socket_path;
	int			sock;
	const char *service;
	const char *func;
	const char *user;
} uw_state_t;


/*
	Logging
*/
static void
uw_log(const uw_state_t *uw, int is_debug, const char *fmt, ...)
{
	char *format;
	va_list ap;
	char pid[12];
	const char *func;
	const char *service;
	const char *user;

	if (is_debug && uw && !uw->debug)
		return;

	func = uw && uw->func ? uw->func : "";
	service = uw && uw->service ? uw->service : "";
	user = uw && uw->user ? uw->user : "";
	sprintf(pid, "%u", (int)getpid());

	format = malloc(strlen(fmt) + strlen(service) + strlen(func)
					+ strlen(user) + strlen(pid) + 32);
	strcpy(format, "pam_userwatch(");
	strcat(format, service);
	strcat(format, "/");
	strcat(format, func);
	strcat(format, ":");
	strcat(format, user);
	strcat(format, ":");
	strcat(format, pid);
	strcat(format, "): ");
	strcat(format, fmt);
	strcat(format, "\n");

	va_start(ap, fmt);
	vsyslog(LOG_AUTHPRIV | LOG_INFO, format, ap);
	va_end(ap);
	free(format);
}


/*
	Parse config file and get unix socket path
*/
static void
uw_parse_config (uw_state_t *uw, const char *config_path)
{
	FILE *file;
	char line[UW_CFG_LINE_MAX];
	char c;
	char *p, *param, *value;
	int  intval;

	file = fopen(config_path, "r");
	if (!file)
		return;

	while (fgets(line, sizeof(line)-1, file)) {
		/* Remove trailing whitespace */
		p = line + strlen(line) - 1;
		while (p >= line && (isspace(*p) || *p == '\r' || *p == '\n'))
			*p-- = 0;

		/* Skip leading whitespace */
		for(p = line; isspace(*p); p++);

		/* Skip empty lines and comments */
		if(!*p || *p == '#')
			continue;

		/* Pull parameter name */
		param = p;
		while(*p && !isspace(*p) && *p != '=') p++;
		if(!*p) continue; /* Syntax error */
		c = *p;
		*p++ = 0;

		/* Skip equal sign and whitespace */
		while(isspace(c)) c = *p++;
		if(c != '=') continue; /* Syntax error */
		while(isspace(*p)) p++;

		value = p;
		/* uw_log(uw, UW_DEBUG, "config: %s=%s", param, value); */

		if (!strcmp(param, "unix_socket")) {
			if (uw->socket_path)
				free(uw->socket_path);
			uw->socket_path = strdup(value);
		}

		if (!strcmp(param, "pam_debug")) {
			intval = atoi(value);
			if (intval)
				uw->debug = 1;
		}
	}

	fclose(file);
}


/*
	Preparation:
		- parse pam_args,
		- get user name and pam initiator name
		- get unix socket path
*/
static uw_state_t *
uw_prepare (const char *func, pam_handle_t *pamh,
			int flags, int argc, const char **argv)
{
	uw_state_t *uw = NULL;
	int i, ret;

	/* Initialize instance descriptor */
	
	ret = pam_get_data(pamh, UW_DATA_NAME, (const void **) &uw);
	if (ret != PAM_SUCCESS || uw == NULL) {
		uw = malloc(sizeof(*uw));
		uw->magic = 0;
	}
	if (uw->magic != UW_MAGIC) {
		memset(uw, 0, sizeof(*uw));
		uw->magic = UW_MAGIC;
		uw->sock = -1;
		ret = pam_set_data(pamh, UW_DATA_NAME, uw, uw_cleanup);
	}

	uw->func = func;

	for (i = 0; i < argc; i++) {
		if (argv[i] && !strcmp(argv[i], "debug")) {
			uw->debug = 1;
		}
		else if (argv[i] && !strcmp(argv[i], "useauthtok")) {
			uw->use_auth_tok = 1;
		}
		uw_log(uw, UW_DEBUG, "option: %s", argv[i] ? argv[i] : "NULL");
	}

	/* Read core information: USER, SERVICE, TTY, RHOST */

	ret = pam_get_user(pamh, &uw->user, NULL);
	if (ret != PAM_SUCCESS) {
		uw_log(uw, UW_ERROR, "cannot get user");
		uw->user = NULL;
	}

	ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &uw->service);
	if (ret != PAM_SUCCESS) {
		uw_log(uw, UW_ERROR, "cannot get service");
		uw->service = NULL;
	}

	/* Read configuration file */

	if (uw->socket_path == NULL) {
		uw_parse_config(uw, UW_CONFIG_FILE);
		if (uw->socket_path == NULL)
			uw->socket_path = strdup(UW_SOCKET_PATH);
		uw_log(uw, UW_DEBUG, "socket_path:%s", uw->socket_path);
	}

	return uw;
}


/*
	Disconnect from uw-client
*/
static void
uw_disconnect (uw_state_t *uw)
{
	if (uw->sock >= 0) {
		uw_log(uw, UW_DEBUG, "disconnected");
		shutdown(uw->sock, SHUT_RDWR);
		close(uw->sock);
		uw->sock = -1;
	}
}


/*
	Cleanup
*/
static void
uw_cleanup (pam_handle_t *pamh, void *data, int error_status)
{
	uw_state_t *uw = data;

	if (uw && uw->magic == UW_MAGIC) {
		uw_disconnect(uw);
		if (uw->socket_path) {
			free(uw->socket_path);
		}
		memset(uw, 0, sizeof(*uw));
	}
}


/*
	Connect to uw-client
*/
static int
uw_connect (uw_state_t *uw)
{
	struct sockaddr_un *paddr;
	int len, sock, ret;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		uw_log(uw, UW_ERROR, "cannot create unix socket: %s", strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	len = sizeof(paddr->sun_family) + strlen(uw->socket_path);
	paddr = (void *) malloc(len + 1);
	paddr->sun_family = AF_UNIX;
	strcpy(paddr->sun_path, uw->socket_path);

	ret = connect(sock, (struct sockaddr *) paddr, len);
	free(paddr);
	if (ret < 0) {
		uw_log(uw, UW_ERROR, "cannot connect unix socket: %s", strerror(errno));
		close(sock);
		return PAM_SYSTEM_ERR;
	}

	uw->sock = sock;
	uw_log(uw, UW_DEBUG, "connected to uw-client", strerror(errno));
	return PAM_SUCCESS;
}

/*
	Send command to uw-client
*/
static int
uw_send (uw_state_t *uw, const char *fmt, ...)
{
	int ret, len, bytes, off;
	char buf[UW_SOCK_BUF_MAX];
	va_list ap;

	if (uw->sock < 0) {
		ret = uw_connect(uw);
		if (ret != PAM_SUCCESS)
			return ret;
	}

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf)-2, fmt, ap);
	va_end(ap);

	if (len >= sizeof(buf)-2) {
		uw_log(uw, UW_ERROR, "request buffer exhausted");
		memset(buf, 0, sizeof(buf));
		return PAM_SYSTEM_ERR;
	}

	strcat(buf, "\n");
	len += 1;
	off = 0;

	while (len > 0) {
		bytes = send(uw->sock, buf+off, len, MSG_NOSIGNAL);
		if (bytes <= 0) {
			if (errno == EINTR)
				continue;
			uw_log(uw, UW_ERROR, "send error: %s", strerror(errno));
			close(uw->sock);
			uw->sock = -1;
			memset(buf, 0, sizeof(buf));
			return PAM_SYSTEM_ERR;
		}
		off += bytes;
		len -= bytes;
	}

	memset(buf, 0, sizeof(buf));
	return PAM_SUCCESS;
}

static int
uw_receive (uw_state_t *uw, char *buf, int buflen)
{
	int off, len, bytes;
	char *p;

	*buf = '\0';
	if (uw->sock < 0)
		return PAM_SYSTEM_ERR;

	off = 0;
	len = buflen;
	while (1) {
		len = buflen - off - 1;
		if (len <= 0) {
			uw_log(uw, UW_ERROR, "reply buffer exhausted");
			return PAM_SYSTEM_ERR;
		}
		bytes = recv(uw->sock, buf+off, len, 0);
		if (bytes <= 0) {
			if (errno == EINTR)
				continue;
			uw_log(uw, UW_ERROR, "receive error: %s", strerror(errno));
			close(uw->sock);
			uw->sock = -1;
			return PAM_SYSTEM_ERR;
		}
		off += bytes;
		buf[off] = '\0';
		p = strchr(buf, '\n');
		if (p) {
			*p = '\0';
			break;
		}
	}

	return PAM_SUCCESS;
}

static int
uw_decode_reply (const char *buf)
{
	if (!strcmp(buf, "success"))
		return PAM_SUCCESS;
	if (!strcmp(buf, "user not found"))
		return PAM_USER_UNKNOWN;
	if (!strcmp(buf, "not implemented"))
		return PAM_CRED_INSUFFICIENT;
	if (!strcmp(buf, "local user auth"))
		return PAM_CRED_INSUFFICIENT;
	if (!strcmp(buf, "invalid password"))
		return PAM_AUTH_ERR;
	return PAM_SYSTEM_ERR;
}


static int
uw_sid (uw_state_t *uw, pam_handle_t *pamh, char *buf, int buflen)
{
	const char *tty;
	const char *rhost;
	char *s;
	int ret, len;

	ret = pam_get_item(pamh, PAM_TTY, (const void **) &tty);
	if (ret != PAM_SUCCESS || tty == NULL)
		tty = "";

	ret = pam_get_item(pamh, PAM_RHOST, (const void **) &rhost);
	if (ret != PAM_SUCCESS || rhost == NULL)
		rhost = "";

	if (strlen(tty) + strlen(rhost) > buflen-2) {
		*buf = '\0';
		uw_log(uw, UW_ERROR, "sid buffer exhausted");
		return PAM_SYSTEM_ERR;
	}

	if (*tty)
		strcpy(buf, tty);
	else
		*buf = '\0';
	if (*rhost) {
		len = strlen(buf);
		buf[len] = '?';
		strcpy(buf+len+1, rhost);
	}

	for (s = buf; *s; s++) {
		if (*s <= 32 || *s >= 127 || strchr("|!@~ \t\r\n", *s))
			*s = '_';
	}

	if (*rhost)
		buf[len] = '@';

	return PAM_SUCCESS;
}


/*
	pam_sm_open_session
	Entrypoint from the PAM layer. Starts the wheels.
	Returns the PAM error code or %PAM_SUCCESS.
*/
PAM_EXTERN EXPORT_SYMBOL int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare("session", pamh, flags, argc, argv);
	char buf[UW_SOCK_BUF_MAX];

	uw_sid(uw, pamh, buf, sizeof(buf));
	if (uw_send(uw, "login %s %s", uw->user, buf) == PAM_SUCCESS) {
		/*uw_receive(uw, buf, sizeof(buf));*/
	}
	memset(buf, 0, sizeof(buf));
	uw_disconnect(uw);

	/* Always success */
	return PAM_SUCCESS;
}


/*
	pam_sm_close_session
	Entry point from the PAM layer. Stops all wheels.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare("session", pamh, flags, argc, argv);
	char buf[UW_SOCK_BUF_MAX];

	uw_sid(uw, pamh, buf, sizeof(buf));
	if (uw_send(uw, "logout %s %s", uw->user, buf) == PAM_SUCCESS) {
		/*uw_receive(uw, buf, sizeof(buf));*/
	}
	memset(buf, 0, sizeof(buf));
	uw_disconnect(uw);

	/* Always success */
	return PAM_SUCCESS;
}


/*
	pam_sm_authenticate
	Placeholder
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare("auth", pamh, flags, argc, argv);
	const char *pass;
	char buf[UW_SOCK_BUF_MAX];
	int ret;

	uw_log(uw, UW_DEBUG, "authenticate user \"%s\"", uw->user);

	if (uw->user == NULL || *(uw->user) == '\0') {
		uw_log(uw, UW_DEBUG, "no user");
		return PAM_AUTH_ERR;
	}

	ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &pass);
	if (ret != PAM_SUCCESS || pass == NULL || *pass == '\0') {
		uw_log(uw, UW_DEBUG, "no password (%d)", ret);
		return PAM_AUTH_ERR;
	}

	ret = uw_send(uw, "auth %s %s", uw->user, pass);
	if (ret == PAM_SUCCESS) {
		ret = uw_receive(uw, buf, sizeof(buf));
		if (ret == PAM_SUCCESS) {
			ret = uw_decode_reply(buf);
			uw_log(uw, UW_DEBUG,
					"got auth for user \"%s\" reply:\"%s\" (%d)",
					uw->user, buf, ret);
		}
	}
	memset(buf, 0, sizeof(buf));
	uw_disconnect(uw);
	if (ret)
		uw_log(uw, UW_DEBUG, "auth error %d", ret);

	return ret;
}


/*
	pam_sm_setcred
	Placeholder.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}


/*
	pam_sm_chauthtok
	Placeholder.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}


/*
	pam_sm_acct_mgmt
	Placeholder.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}


#ifdef PAM_STATIC
/* static module data */
EXPORT_SYMBOL struct pam_module _pam_uwatch_modstruct = {
	.name					= "pam_uwatch",
	.pam_sm_authenticate	= pam_sm_authenticate,
	.pam_sm_setcred			= pam_sm_setcred,
	.pam_sm_acct_mgmt		= pam_sm_acct_mgmt,
	.pam_sm_open_sesion		= pam_sm_open_session,
	.pam_sm_close_session	= pam_sm_close_session,
	.pam_sm_chauthtok		= pam_sm_chauthtok,
};
#endif

/********************************************************/

