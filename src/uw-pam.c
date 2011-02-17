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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pwd.h>

#include "config.h"

#ifdef HAVE_VISIBILITY_HIDDEN
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#else
#define EXPORT_SYMBOL
#endif


typedef struct {
	int			debug;
	const char *user;
} uw_state_t;


static void
uw_log(const uw_state_t *uw, int is_debug, const char *fmt, ...)
{
	char *format;
	va_list ap;
	if (is_debug && NULL != uw && !uw->debug)
		return;
	format = malloc(strlen(fmt) + 32);
	strcpy(format, "pam_userwatch(): ");
	strcat(format, fmt);
	strcat(format, "\n");
	va_start(ap, fmt);
	vsyslog(LOG_AUTHPRIV | LOG_INFO, format, ap);
	va_end(ap);
	free(format);
}


/*
	Preparation:
		- parse pam_args,
		- get user name and pam initiator name
		- get unix socket path
*/
static uw_state_t *
uw_prepare(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = NULL;
	int i, ret;

	uw = malloc(sizeof(*uw));
	memset(uw, 0, sizeof(*uw));
	uw->debug = 1;

	for (i = 0; i < argc; i++) {
		uw_log(uw, 1, "option: %s", argv[i] ? argv[i] : "NULL");
	}

	ret = pam_get_user(pamh, &uw->user, NULL);
	if (ret != PAM_SUCCESS) {
		uw_log(uw, 0, "cannot get user");
		uw->user = NULL;
	}
	uw_log(uw, 1, "user:%s", uw->user);

	return uw;
}


/*
	pam_sm_open_session
	Entrypoint from the PAM layer. Starts the wheels.
	Returns the PAM error code or %PAM_SUCCESS.
*/
PAM_EXTERN EXPORT_SYMBOL int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare(pamh, flags, argc, argv);
	uw_log(uw, 1, "open session");
	return PAM_SUCCESS;
}


/*
	pam_sm_close_session
	Entry point from the PAM layer. Stops all wheels.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare(pamh, flags, argc, argv);
	uw_log(uw, 1, "close session");
	return PAM_SUCCESS;
}


/*
	pam_sm_authenticate
	Placeholder
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare(pamh, flags, argc, argv);
	uw_log(uw, 1, "authenticate");
	return PAM_SUCCESS;
}


/*
	pam_sm_setcred
	Placeholder.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare(pamh, flags, argc, argv);
	uw_log(uw, 1, "setcred");
	return PAM_SUCCESS;
}


/*
	pam_sm_chauthtok
	Placeholder.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare(pamh, flags, argc, argv);
	uw_log(uw, 1, "chauthtok");
	return PAM_SUCCESS;
}


/*
	pam_sm_acct_mgmt
	Placeholder.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uw_state_t *uw = uw_prepare(pamh, flags, argc, argv);
	uw_log(uw, 1, "acct_mgmt");
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

