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
#include <pwd.h>

#include "uwcli.h"

#ifdef HAVE_VISIBILITY_HIDDEN
#define EXPORT_SYMBOL __attribute__((visibility("default")))
#else
#define EXPORT_SYMBOL
#endif

#define __STRINGIFY_2(x)	#x
#define __STRINGIFY(x)		__STRINGIFY_2(x)

#define PMPREFIX "pam_uwatch(" __STRINGIFY(__LINE__) ") "


static void
l0g(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_AUTHPRIV | LOG_ERR, fmt, ap);
	va_end(ap);
}


/*
	parse_pam_args
*/
static void
parse_pam_args(int argc, const char **argv)
{
	int i;

	/* first, set default values */
	for (i = 0; i < argc; i++) {
		l0g(PMPREFIX "pam_uwatch option: %s\n", argv[i] ? argv[i] : "NULL");
	}
}


/*
	modify_usecount
	Adjusts the user reference count.
	Returns the new reference count value on success, or -1 on error.
	Note: Modified version of pam_console.c:use_count()
*/
static int
modify_usecount(const char *user, int op)
{
	int val = -1;
	assert(user != NULL);
	return val;
}


/*
	pam_sm_open_session
	Entrypoint from the PAM layer. Starts the wheels.
	Returns the PAM error code or %PAM_SUCCESS.
*/
PAM_EXTERN EXPORT_SYMBOL int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int ret = PAM_SUCCESS;
	const char *pam_user = NULL;

	/* call pam_get_user again because ssh calls PAM from seperate processes. */
	ret = pam_get_user(pamh, &pam_user, NULL);
	if (ret != PAM_SUCCESS) {
		l0g(PMPREFIX "could not get user");
		/* do NOT return PAM_SERVICE_ERR or root will not be able to su */
		goto _return;
	}

	parse_pam_args(argc, argv);

	ret = 0; // readconfig();
	if (ret < 0) {
		ret = PAM_SERVICE_ERR;
		goto _return;
	}

	l0g(PMPREFIX "%s: real uid/gid=%ld:%ld, effective uid/gid=%ld:%ld\n",
		pam_user, (long) getuid(), (long) getgid(),
		(long) geteuid(), (long) getegid());
	modify_usecount(pam_user, 1);

_return:
	l0g(PMPREFIX "done opening session\n");
	return ret;
}


/*
	pam_sm_authenticat
	Placeholder
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
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
	return pam_sm_authenticate(pamh, flags, argc, argv);
}


/*
	pam_sm_close_session
	Entrypoint from the PAM layer. Stops all wheels.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int ret = PAM_SUCCESS;
	const char *pam_user = NULL;

	l0g(PMPREFIX "pam_uwatch: uid = %d , euid = %d.\n", getuid(), geteuid());
	/* call pam_get_user again because ssh calls PAM fns from separate processes. */
	ret = pam_get_user(pamh, &pam_user, NULL);
	if (ret != PAM_SUCCESS) {
		l0g(PMPREFIX "could not get user\n");
		/* DONT return PAM_SERVICE_ERR or root won't be able to su to other users */
		goto _return;
	}

	parse_pam_args(argc, argv);

	if (modify_usecount(pam_user, -1) <= 0) {
		l0g(PMPREFIX "%s - all sessions closed\n", pam_user);
	} else {
		l0g(PMPREFIX "%s seems to have other remaining open sessions\n", pam_user);
	}
_return:
	/* Note that config is automatically freed later in clean_config(). */
	l0g(PMPREFIX "pam_uwatch execution complete\n");
	return ret;
}


/*
	pam_sm_setcred
	Placeholder.
*/
PAM_EXTERN EXPORT_SYMBOL
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
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
    return PAM_IGNORE;
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

