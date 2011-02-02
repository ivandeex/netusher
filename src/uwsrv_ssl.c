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
#include <unistd.h>
#include <netinet/in.h>
#include <sys/wait.h>

#include "uwsrv.h"


SSL_CTX *ctx;
SSL *ssl;
BIO *conn;
int sock, connfd;


int
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
	char *pass = UW_SRV_KEY_PASS;
	if (NULL == pass)
		return 0;
	if (num < strlen(pass) + 1)
		return 0;
	strcpy(buf, pass);
	return strlen(pass);
}


static int
ssl_verify_cb(int preverify_ok, X509_STORE_CTX * ctx)
{
	char subj[256];

	/* get the X509 name */
	X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), subj, sizeof subj);
	subj[sizeof(subj) - 1] = '\0';
	if (!preverify_ok) {
		/* peer presented cert not signed by our root cert */
		printf("client cert rejected (%s): %s\n",
				X509_verify_cert_error_string(ctx->error), subj);
		ERR_clear_error ();
		/* reject connection */
		return 0;
    }
	printf("client cert ok: %s\n", subj);
	/* accept connection */
	return 1;
}


/*
	SSL routine
*/
int
ssl_startup(void)
{
	STACK_OF(X509_NAME) *cacerts;
	int ret, opt;
	struct sockaddr_in addr;

	SSL_library_init();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_server_method());

	if (! SSL_CTX_use_certificate_file(ctx, UW_SRV_CERT_FILE, SSL_FILETYPE_PEM)) {
		return ssl_err("cannot read certificate %s\n", UW_SRV_CERT_FILE);
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (! SSL_CTX_use_PrivateKey_file(ctx, UW_SRV_KEY_FILE, SSL_FILETYPE_PEM)) {
		printf("cannot read private key %s\n", UW_SRV_KEY_FILE);
		ERR_print_errors_fp(stderr);
		return -1;
	}

	SSL_CTX_set_default_passwd_cb(ctx, ssl_password_cb);

	if (! SSL_CTX_load_verify_locations(ctx, UW_CA_FILE, NULL)) {
		printf("cannot load CA list %s\n", UW_CA_FILE);
		ERR_print_errors_fp(stderr);
		return -1;
	}

	SSL_CTX_set_verify(ctx,
						SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						ssl_verify_cb);

	cacerts = SSL_load_client_CA_file(UW_CA_FILE);
	if (NULL == cacerts) {
		printf("cannot load CA names from %s\n", UW_CA_FILE);
		ERR_print_errors_fp(stderr);
		return -1;
	}
	SSL_CTX_set_client_CA_list (ctx, cacerts);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("cannot open server socket");
		return -1;
	}

	opt = 1;
	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof opt);
	if (ret < 0) {
		perror("SERV/SO_REUSEADDR");
		return -1;
	}

	bzero(&addr, sizeof addr);
	addr.sin_port = htons(UW_PORT);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	ret = bind(sock, (struct sockaddr *) &addr, sizeof addr);
  	if (ret < 0) {
		perror("cannot bind server socket");
		return -1;
	}
	listen(sock, 4);

	return 0;
}


int
rip_children(void)
{
	int ret, status;
	do {
		ret = waitpid(-1, &status, WNOHANG);
		printf("waitpid returned %d\n", ret);
	} while (ret != -1 && ret != 0);
	return 0;
}


int
ssl_server(void)
{
	int connfd;
	int alen;
	struct sockaddr_in addr;
	pid_t pid;

	if (ssl_startup() < 0)
		return -1;

	while (1) {
		connfd = accept(sock, (struct sockaddr *) &addr, (socklen_t *) &alen);
		if (connfd < 0) {
			perror("accept() failed");
			continue;
		}
		pid = fork();
		if (pid == -1) {
			perror("fork() failed");
			continue;
		}
		if (pid == 0)
			ssl_child(connfd);
		rip_children();
	}
}


int
ssl_child(int _connfd)
{
	char buf[UW_BUFSIZE];

	if (ssl_child_open(_connfd) == 0) {
		while (ssl_get(buf, sizeof buf) >= 0) {
			if (handle_request(buf) != 0) {
				break;
			}
		}
	}
	ssl_child_close();
	exit(0);
}


int
ssl_child_open(int _connfd)
{	
	BIO *bio;
	int ret;

	connfd = _connfd;

	bio = BIO_new_socket(connfd, BIO_NOCLOSE);
	ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);

	ret = SSL_accept(ssl);
	if (ret <= 0) {
		printf("SSL accept failed\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	bio = BIO_new(BIO_f_ssl());
	BIO_set_ssl(bio, ssl, BIO_CLOSE);
	conn = BIO_new(BIO_f_buffer());
	BIO_push(conn, bio);

	return 0;
}


int
ssl_child_close(void)
{
	int ret;

	ret = SSL_shutdown(ssl);
	if (ret == 0){
		shutdown(connfd, 1);
		ret = SSL_shutdown(ssl);
	}

	if (ret <= 0) {
		printf("SSL shutdown failed\n");
		ERR_print_errors_fp(stderr);
	}

	SSL_free(ssl);
	close(connfd);

	SSL_CTX_free(ctx);
	return 0;
}


int
ssl_put(const char *fmt, ...)
{
	char buf[UW_BUFSIZE];
	va_list ap;
	int ret;

	if (connfd < 0)
		return -1;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	va_end(ap);
	strcat(buf, "\n");

	printf("SERVER> %s", buf);

	ret = BIO_puts(conn, buf);
	if (ret <= 0 || BIO_flush(conn) <= 0) {
		printf("Error writing to client\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}


int
ssl_get(char *buf, int bufsize)
{
	int ret, len;

	if (bufsize < 2 || connfd < 0)
		return -1;

	ret = BIO_gets(conn, buf, bufsize-1);
	if (SSL_get_error(ssl, ret) != SSL_ERROR_NONE) {
		printf("Error reading from client\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	len = strlen(buf);
	while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n'))
		len--;
	buf[len] = 0;

	return len;
}



