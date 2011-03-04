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

  NetUsher PAM module.

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
#include <ctype.h>
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

#define NU_DEBUG	1
#define NU_ERROR	0

#define NU_CONFIG_FILE 	"/etc/netusher/nu-client.conf"
#define NU_SOCKET_PATH	"/var/run/netusher/nu-client.sock"
#define NU_DATA_NAME	"pam_netusher_data"
#define NU_MAGIC		0x5A61C
#define NU_CFG_LINE_MAX	256
#define NU_SOCK_BUF_MAX	128

static void nu_cleanup (pam_handle_t *, void *, int);

typedef struct {
	int			magic;
	int			debug;
	int			use_auth_tok;
	char *		socket_path;
	int			sock;
	const char *service;
	const char *func;
	const char *user;
} nu_state_t;


/*
	Logging
*/
static void
nu_log(const nu_state_t *nu, int is_debug, const char *fmt, ...)
{
	char *format;
	va_list ap;
	char pid[12];
	const char *func;
	const char *service;
	const char *user;

	if (is_debug && nu && !nu->debug)
		return;

	func = nu && nu->func ? nu->func : "";
	service = nu && nu->service ? nu->service : "";
	user = nu && nu->user ? nu->user : "";
	sprintf(pid, "%u", (int)getpid());

	format = malloc(strlen(fmt) + strlen(service) + strlen(func)
					+ strlen(user) + strlen(pid) + 32);
	strcpy(format, "pam_netusher(");
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
nu_parse_config (nu_state_t *nu, const char *config_path)
{
	FILE *file;
	char line[NU_CFG_LINE_MAX];
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
		/* nu_log(nu, NU_DEBUG, "config: %s=%s", param, value); */

		if (!strcmp(param, "unix_socket")) {
			if (nu->socket_path)
				free(nu->socket_path);
			nu->socket_path = strdup(value);
		}

		if (!strcmp(param, "pam_debug")) {
			intval = atoi(value);
			if (intval)
				nu->debug = 1;
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
static nu_state_t *
nu_prepare (const char *func, pam_handle_t *pamh,
			int flags, int argc, const char **argv)
{
	nu_state_t *nu = NULL;
	int i, ret;

	/* Initialize instance descriptor */
	
	ret = pam_get_data(pamh, NU_DATA_NAME, (const void **) &nu);
	if (ret != PAM_SUCCESS || nu == NULL) {
		nu = malloc(sizeof(*nu));
		nu->magic = 0;
	}
	if (nu->magic != NU_MAGIC) {
		memset(nu, 0, sizeof(*nu));
		nu->magic = NU_MAGIC;
		nu->sock = -1;
		ret = pam_set_data(pamh, NU_DATA_NAME, nu, nu_cleanup);
	}

	nu->func = func;

	for (i = 0; i < argc; i++) {
		if (argv[i] && !strcmp(argv[i], "debug")) {
			nu->debug = 1;
		}
		else if (argv[i] && !strcmp(argv[i], "useauthtok")) {
			nu->use_auth_tok = 1;
		}
		nu_log(nu, NU_DEBUG, "option: %s", argv[i] ? argv[i] : "NULL");
	}

	/* Read core information: USER, SERVICE, TTY, RHOST */

	ret = pam_get_user(pamh, &nu->user, NULL);
	if (ret != PAM_SUCCESS) {
		nu_log(nu, NU_ERROR, "cannot get user");
		nu->user = NULL;
	}

	ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &nu->service);
	if (ret != PAM_SUCCESS) {
		nu_log(nu, NU_ERROR, "cannot get service");
		nu->service = NULL;
	}

	/* Read configuration file */

	if (nu->socket_path == NULL) {
		nu_parse_config(nu, NU_CONFIG_FILE);
		if (nu->socket_path == NULL)
			nu->socket_path = strdup(NU_SOCKET_PATH);
		nu_log(nu, NU_DEBUG, "socket_path:%s", nu->socket_path);
	}

	return nu;
}


/*
	Disconnect from nu-client
*/
static void
nu_disconnect (nu_state_t *nu)
{
	if (nu->sock >= 0) {
		nu_log(nu, NU_DEBUG, "disconnected");
		shutdown(nu->sock, SHUT_RDWR);
		close(nu->sock);
		nu->sock = -1;
	}
}


/*
	Cleanup
*/
static void
nu_cleanup (pam_handle_t *pamh, void *data, int error_status)
{
	nu_state_t *nu = data;

	if (nu && nu->magic == NU_MAGIC) {
		nu_disconnect(nu);
		if (nu->socket_path) {
			free(nu->socket_path);
		}
		memset(nu, 0, sizeof(*nu));
	}
}


/*
	Connect to nu-client
*/
static int
nu_connect (nu_state_t *nu)
{
	struct sockaddr_un *paddr;
	int len, sock, ret;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		nu_log(nu, NU_ERROR, "cannot create unix socket: %s", strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	len = sizeof(paddr->sun_family) + strlen(nu->socket_path);
	paddr = (void *) malloc(len + 1);
	paddr->sun_family = AF_UNIX;
	strcpy(paddr->sun_path, nu->socket_path);

	ret = connect(sock, (struct sockaddr *) paddr, len);
	free(paddr);
	if (ret < 0) {
		nu_log(nu, NU_ERROR, "cannot connect unix socket: %s", strerror(errno));
		close(sock);
		return PAM_SYSTEM_ERR;
	}

	nu->sock = sock;
	nu_log(nu, NU_DEBUG, "connected to nu-client", strerror(errno));
	return PAM_SUCCESS;
}

/*
	Send command to nu-client
*/
static int
nu_send (nu_state_t *nu, const char *fmt, ...)
{
	int ret, len, bytes, off;
	char buf[NU_SOCK_BUF_MAX];
	va_list ap;

	if (nu->sock < 0) {
		ret = nu_connect(nu);
		if (ret != PAM_SUCCESS)
			return ret;
	}

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf)-2, fmt, ap);
	va_end(ap);

	if (len >= sizeof(buf)-2) {
		nu_log(nu, NU_ERROR, "request buffer exhausted");
		memset(buf, 0, sizeof(buf));
		return PAM_SYSTEM_ERR;
	}

	strcat(buf, "\n");
	len += 1;
	off = 0;

	while (len > 0) {
		bytes = send(nu->sock, buf+off, len, MSG_NOSIGNAL);
		if (bytes <= 0) {
			if (errno == EINTR)
				continue;
			nu_log(nu, NU_ERROR, "send error: %s", strerror(errno));
			close(nu->sock);
			nu->sock = -1;
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
nu_receive (nu_state_t *nu, char *buf, int buflen)
{
	int off, len, bytes;
	char *p;

	*buf = '\0';
	if (nu->sock < 0)
		return PAM_SYSTEM_ERR;

	off = 0;
	len = buflen;
	while (1) {
		len = buflen - off - 1;
		if (len <= 0) {
			nu_log(nu, NU_ERROR, "reply buffer exhausted");
			return PAM_SYSTEM_ERR;
		}
		bytes = recv(nu->sock, buf+off, len, 0);
		if (bytes <= 0) {
			if (errno == EINTR)
				continue;
			nu_log(nu, NU_ERROR, "receive error: %s", strerror(errno));
			close(nu->sock);
			nu->sock = -1;
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
nu_decode_reply (const char *buf)
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
nu_sid (nu_state_t *nu, pam_handle_t *pamh, char *buf, int buflen)
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
		nu_log(nu, NU_ERROR, "sid buffer exhausted");
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
	} else {
		len = -1;
	}

	for (s = buf; *s; s++) {
		if (*s <= 32 || *s >= 127 || strchr("|!@~ \t\r\n", *s))
			*s = '_';
	}

	if (len >= 0)
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
	nu_state_t *nu = nu_prepare("session", pamh, flags, argc, argv);
	char buf[NU_SOCK_BUF_MAX];

	nu_sid(nu, pamh, buf, sizeof(buf));
	if (nu_send(nu, "login %s %s", nu->user, buf) == PAM_SUCCESS) {
		/* Wait until nu-client finishes group mirroring */
		nu_receive(nu, buf, sizeof(buf));
	}
	memset(buf, 0, sizeof(buf));
	nu_disconnect(nu);

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
	nu_state_t *nu = nu_prepare("session", pamh, flags, argc, argv);
	char buf[NU_SOCK_BUF_MAX];

	nu_sid(nu, pamh, buf, sizeof(buf));
	if (nu_send(nu, "logout %s %s", nu->user, buf) == PAM_SUCCESS) {
		/* Exit without waiting for nu-client. */
		/*nu_receive(nu, buf, sizeof(buf));*/
	}
	memset(buf, 0, sizeof(buf));
	nu_disconnect(nu);

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
	nu_state_t *nu = nu_prepare("auth", pamh, flags, argc, argv);
	const char *pass;
	char buf[NU_SOCK_BUF_MAX];
	int ret;

	nu_log(nu, NU_DEBUG, "authenticate user \"%s\"", nu->user);

	if (nu->user == NULL || *(nu->user) == '\0') {
		nu_log(nu, NU_DEBUG, "no user");
		return PAM_AUTH_ERR;
	}

	ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &pass);
	if (ret != PAM_SUCCESS || pass == NULL || *pass == '\0') {
		nu_log(nu, NU_DEBUG, "no password (%d)", ret);
		return PAM_AUTH_ERR;
	}

	ret = nu_send(nu, "auth %s %s", nu->user, pass);
	if (ret == PAM_SUCCESS) {
		ret = nu_receive(nu, buf, sizeof(buf));
		if (ret == PAM_SUCCESS) {
			ret = nu_decode_reply(buf);
			nu_log(nu, NU_DEBUG,
					"got auth for user \"%s\" reply:\"%s\" (%d)",
					nu->user, buf, ret);
		}
	}
	memset(buf, 0, sizeof(buf));
	nu_disconnect(nu);
	if (ret)
		nu_log(nu, NU_DEBUG, "auth error %d", ret);

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
EXPORT_SYMBOL struct pam_module _pam_netusher_modstruct = {
	.name					= "pam_netusher",
	.pam_sm_authenticate	= pam_sm_authenticate,
	.pam_sm_setcred			= pam_sm_setcred,
	.pam_sm_acct_mgmt		= pam_sm_acct_mgmt,
	.pam_sm_open_sesion		= pam_sm_open_session,
	.pam_sm_close_session	= pam_sm_close_session,
	.pam_sm_chauthtok		= pam_sm_chauthtok,
};
#endif

/********************************************************/

