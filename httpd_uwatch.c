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

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "util_script.h"


typedef struct {
	int		enabled;
#if UWATCH_SCAN_PROXY
	int		scan_proxy;
#endif /* UWATCH_SCAN_PROXY */
	int		out_notes;
	int		out_env;
	char *	server;
} uwatch_server_config_rec;

#define uwatch_conf uwatch_server_config_rec

module AP_MODULE_DECLARE_DATA uwatch_module;

static const char * not_alloc = "mod_uwatch: server structure not allocated";


#if 0
static void *
create_uwatch_conf(apr_pool_t *p, server_rec *d)
{
	uwatch_conf *conf = (uwatch_conf *) apr_pcalloc(p, sizeof(uwatch_conf));
	if (NULL == conf)
		return NULL;
	conf->enabled = 0;
	conf->scan_proxy = 0;
	conf->out_notes = 0;
	conf->out_env = 0;
	conf->server = NULL;
	return (void *) conf;
}
#endif


static apr_status_t
uwatch_cleanup(void *cfgdata)
{
	uwatch_conf *conf = (uwatch_conf *) cfgdata;
	conf++;
	return APR_SUCCESS;
}


static void
uwatch_child_init(apr_pool_t *p, server_rec *s)
{
	uwatch_conf *conf = (uwatch_conf *)
			ap_get_module_config(s->module_config,  &uwatch_module);
	apr_pool_cleanup_register(p, (void *) conf, uwatch_cleanup, uwatch_cleanup);
}


static int
uwatch_post_read_request(request_rec *r)
{
	char *ipaddr;
	uwatch_conf *conf = (uwatch_conf *)
			ap_get_module_config(r->server->module_config, &uwatch_module);
	if (NULL == conf || !conf->enabled) {
		return DECLINED;
	}

	ipaddr = r->connection->remote_ip;

#if UWATCH_SCAN_PROXY
	if (conf->scan_proxy) {
		static const char *headers[] = {
			"HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR",
			"X-Forwarded-For", "HTTP_REMOTE_ADDR",
			NULL
		};
		char *ipaddr_p = NULL;
		char *comma_p;
		int i;
		ap_add_common_vars(r);
		for (i = 0; NULL != ipaddr_p && NULL != headers[i]; i++) {
			if (apr_table_get(r->subprocess_env, headers[i])) {
				ipaddr_p = (char *) apr_table_get(r->subprocess_env, headers[i]);
			}
		}
		if (NULL == ipaddr_p) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG,0, r->server,
				"mod_uwatch: cannot get IP from proxy headers. Using REMOTE_ADDR.");
		} else {
	  		ap_log_error(APLOG_MARK, APLOG_DEBUG,0, r->server,
				"mod_uwatch: IPADDR_PTR: %s", ipaddr_p);
			/*
				Check to ensure that the HTTP_CLIENT_IP or X-Forwarded-For
				header is not a comma separated list of addresses. If the
				header is a comma separated list, return the first IP address
				in the list, which is (hopefully!) the real client IP.
			*/
			ipaddr = (char *) calloc(16, sizeof(char));
			strncpy(ipaddr, ipaddr_p, 15);
			ipaddr[15] = 0;
			comma_p = strchr(ipaddr, ',');
			if (comma_p)  *comma_p = 0;
		}
	}
#endif /* UWATCH_SCAN_PROXY */

	if (conf->out_notes)
		apr_table_setn(r->notes, "UWATCH_IP", ipaddr);
	if (conf->out_env)
		apr_table_setn(r->subprocess_env, "UWATCH_IP", ipaddr);
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server,
				"[mod_uwatch]: IP = %s", ipaddr);
	return OK;
}


#if UWATCH_SCAN_PROXY
static const char *
set_uwatch_scan_proxy(cmd_parms *cmd, void *dummy, int arg)
{
	uwatch_conf *conf = (uwatch_conf *)
			ap_get_module_config(cmd->server->module_config, &uwatch_module);
	if (NULL == conf)
		return not_alloc;
	conf->scan_proxy = arg;
	return NULL;
}
#endif /* UWATCH_SCAN_PROXY */


static const char *
set_uwatch_out_notes(cmd_parms *cmd, void *dummy, int arg)
{
	uwatch_conf *conf = (uwatch_conf *)
			ap_get_module_config(cmd->server->module_config, &uwatch_module);
	if (NULL == conf)
		return not_alloc;
	conf->out_notes = arg;
	return NULL;
}


static const char *
set_uwatch_out_env(cmd_parms *cmd, void *dummy, int arg)
{
	uwatch_conf *conf = (uwatch_conf *)
			ap_get_module_config(cmd->server->module_config, &uwatch_module);
	if (NULL == conf)
		return not_alloc;
	conf->out_env = arg;
	return NULL;
}


static const char *
set_uwatch_enable(cmd_parms *cmd, void *dummy, int arg)
{
	uwatch_conf *conf = (uwatch_conf *)
			ap_get_module_config(cmd->server->module_config, &uwatch_module);
	if (NULL == conf)
		return not_alloc;
	conf->enabled = arg;
	return NULL;
}


static const char *
set_uwatch_server(cmd_parms *cmd, void *dummy, const char *arg1, const char *arg2)
{
	uwatch_conf *conf = (uwatch_conf *)
			ap_get_module_config(cmd->server->module_config, &uwatch_module);
	if (NULL == arg1)
		return NULL;

	conf->server = (char *) apr_pstrdup(cmd->pool, arg1);
	/* arg2 ignored for now */
	return NULL;
}


static const command_rec
uwatch_cmds[] = 
{
#if UWATCH_SCAN_PROXY
	AP_INIT_FLAG( "UWatchScanProxy", set_uwatch_scan_proxy, NULL, OR_FILEINFO,
				"Get IP from HTTP_CLIENT IP or X-Forwarded-For"),
#endif /* UWATCH_SCAN_PROXY */
	AP_INIT_FLAG( "UWatchEnable", set_uwatch_enable, NULL, OR_FILEINFO,
				"Turn on mod_uwatch"),
	AP_INIT_FLAG( "UWatchOutNotes", set_uwatch_out_notes, NULL, OR_FILEINFO,
				"Output data in notes"),
	AP_INIT_FLAG( "UWatchOutEnv", set_uwatch_out_env, NULL, OR_FILEINFO,
				"Output data in env"),
	AP_INIT_TAKE12("UWatchServer", set_uwatch_server, NULL, OR_FILEINFO,
				"Hostname of UserWatch server"),
	{NULL}
};


static void *
uwatch_make(apr_pool_t *p, server_rec *s)
{
	uwatch_conf *conf = (uwatch_conf *) apr_pcalloc(p, sizeof(uwatch_conf));
	conf->enabled = 0;
#if UWATCH_SCAN_PROXY
	conf->scan_proxy = 0;
#endif /* UWATCH_SCAN_PROXY */
	conf->out_notes = 0;
	conf->out_env = 0;
	conf->server = NULL;
	return conf;
}


static void
uwatch_register_hooks(apr_pool_t *p)
{
	ap_hook_post_read_request(uwatch_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(uwatch_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA uwatch_module =
{
	STANDARD20_MODULE_STUFF, 
	NULL,					/* create per-dir    config structures */
	NULL,					/* merge  per-dir    config structures */
	uwatch_make,			/* create per-server config structures */
	NULL,					/* merge  per-server config structures */
	uwatch_cmds,			/* table of config file commands       */
	uwatch_register_hooks	/* register hooks                      */
};

