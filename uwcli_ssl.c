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
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>

#include "uwcli.h"


typedef struct {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *conn;
	int  sock;
} uwcli_state;

static uwcli_state uwcli;

static int
ssl_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	ERR_print_errors_fp(stderr);
	return -1;
}


static int
ssl_password_cb(char *buf, int num, int rwflag, void *userdata)
{
	char *pass = UW_CLI_KEY_PASS;
	if (NULL == pass)
		return 0;
	if (num < strlen(pass) + 1)
		return 0;
	strcpy(buf, pass);
	return strlen(pass);
}


/*
	SSL routine
*/
int
uwcli_open (void)
{
	BIO *bio;
	int ret;
	struct sockaddr_in addr;
	struct hostent hostres, *hostp;
	char hostbuf[UW_BUFSIZE];
	int hosterr;

	if (uwcli.sock)
		return -1;

	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	uwcli.ctx = SSL_CTX_new(SSLv23_client_method());

	if (! SSL_CTX_use_certificate_file(uwcli.ctx,
						UW_CLI_CERT_FILE, SSL_FILETYPE_PEM)) {
		ssl_err("cannot read certificate %s\n", UW_CLI_CERT_FILE);
		SSL_CTX_free(uwcli.ctx);
		return -1;
	}

	if (! SSL_CTX_use_PrivateKey_file(uwcli.ctx,
						UW_CLI_KEY_FILE, SSL_FILETYPE_PEM)) {
		ssl_err("cannot read private key %s\n", UW_CLI_KEY_FILE);
		SSL_CTX_free(uwcli.ctx);
		return -1;
	}

	SSL_CTX_set_default_passwd_cb(uwcli.ctx, ssl_password_cb);

	ret = gethostbyname_r(UW_HOST, &hostres, hostbuf, sizeof(hostbuf)-1,
							&hostp, &hosterr);
	if (ret < 0) {
		printf("%s: cannot resolve host\n", UW_HOST);
		SSL_CTX_free(uwcli.ctx);
		return -1;
	}

	bzero(&addr, sizeof addr);
	addr.sin_family = hostres.h_addrtype;
	bcopy(hostres.h_addr, &addr.sin_addr, hostres.h_length);
	addr.sin_port = htons(UW_PORT);

	uwcli.sock = socket(AF_INET, SOCK_STREAM, 0);
	if (uwcli.sock <= 0) {
		perror("cannot open server socket");
		SSL_CTX_free(uwcli.ctx);
		uwcli.sock = 0;
		return -1;
	}

	ret = connect(uwcli.sock, (struct sockaddr *) &addr, sizeof addr);
  	if (ret < 0) {
		perror("cannot connect to server");
		SSL_CTX_free(uwcli.ctx);
		close(uwcli.sock);
		uwcli.sock = 0;
		return -1;
	}

	bio = BIO_new_socket(uwcli.sock, BIO_NOCLOSE);
	uwcli.ssl = SSL_new(uwcli.ctx);
	SSL_set_bio(uwcli.ssl, bio, bio);

	ret = SSL_connect(uwcli.ssl);
	if (ret <= 0) {
		SSL_free(uwcli.ssl);
		SSL_CTX_free(uwcli.ctx);
		close(uwcli.sock);
		uwcli.sock = 0;
		return ssl_err("SSL connect failed");
	}

	bio = BIO_new(BIO_f_ssl());
	BIO_set_ssl(bio, uwcli.ssl, BIO_CLOSE);
	uwcli.conn = BIO_new(BIO_f_buffer());
	BIO_push(uwcli.conn, bio);

	return 0;
}


int
uwcli_put(const char *fmt, ...)
{
	char buf[UW_BUFSIZE];
	va_list ap;
	int ret;

	if (uwcli.sock == 0)
		return -1;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	va_end(ap);
	strcat(buf, "\n");

	ret = BIO_puts(uwcli.conn, buf);
	if (ret <= 0 || BIO_flush(uwcli.conn) <= 0)
		return ssl_err("error writing to server");

	return 0;
}


int
uwcli_get(char *buf, int bufsize)
{
	int ret, len;

	if (bufsize < 2 || uwcli.sock == 0)
		return -1;

	ret = BIO_gets(uwcli.conn, buf, bufsize-1);
	if (SSL_get_error(uwcli.ssl, ret) != SSL_ERROR_NONE)
		return ssl_err("error reading from server");

	len = strlen(buf);
	while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n'))
		len--;
	buf[len] = 0;

	return len;
}


int
uwcli_close(void)
{
	int ret;

	if (uwcli.sock == 0)
		return -1;

	ret = SSL_shutdown(uwcli.ssl);
	if (ret == 0){
		shutdown(uwcli.sock, 1);
		ret = SSL_shutdown(uwcli.ssl);
	}

	if (ret <= 0)
		ssl_err("SSL shutdown failed (ret=%d)", ret);

	SSL_free(uwcli.ssl);
	SSL_CTX_free(uwcli.ctx);

	close(uwcli.sock);
	uwcli.sock = 0;

	return 0;
}


