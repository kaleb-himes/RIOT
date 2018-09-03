/*
 * **** This file incorporates work covered by the following copyright and ****
 * **** permission notice:                                                 ****
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <net/sock.h>
#include <wolfssl/ssl.h>
static int wolfssl_is_initialized = 0;

#define MODE_TLS 0
#define MODE_DTLS 1

void dtls_socket_close(sock_tls_t *sk)
{
    sock_udp_close(&sk->conn.udp);
    wolfSSL_free(sk->ssl);
}


void dtls_set_endpoint(sock_tls_t *sk, const sock_udp_ep_t *addr)
{
    printf("wolfSSL: Setting peer address and port\n");
    memcpy(&sk->peer_addr, addr, sizeof (sock_udp_ep_t));
}

ssize_t sock_tls_read(sock_tls_t *  sock, 
        void        * data, 
        size_t  	max_len)
{
    return wolfSSL_read(sock->ssl, data, max_len);
}

ssize_t sock_tls_write(sock_tls_t *sock, const void *data, size_t max_len)
{
    return wolfSSL_write(sock->ssl, data, max_len);
}

int sock_dtls_create(sock_tls_t *sock, const sock_udp_ep_t *local, const sock_udp_ep_t *remote, uint16_t flags, WOLFSSL_METHOD *method)
{
    int ret;
    if (!wolfssl_is_initialized) {
        wolfSSL_Init();
        wolfSSL_Debugging_ON();
        wolfssl_is_initialized++;
    }
    if (!sock)
        return -EINVAL;
    XMEMSET(&sock, 0, sizeof(sock_tls_t));
    sock->ctx = wolfSSL_CTX_new(method);
    if (!sock->ctx)
        return -ENOMEM;

    ret = sock_udp_create(&sock->conn.udp, local, remote, flags);
    if (ret < 0) {
        XFREE(sock->ctx, NULL, 0);
        return ret;
    }
    sock->ssl = wolfSSL_new(sock->ctx);
    if (!sock->ssl) {
        sock_udp_close(&sock->conn.udp);
        XFREE(sock->ctx, NULL, 0);
        return -ENOMEM;
    }
    wolfSSL_SetIOReadCtx(sock->ssl, sock);
    wolfSSL_SetIOWriteCtx(sock->ssl, sock);
    if (remote) {
        XMEMCPY(&sock->peer_addr, remote, sizeof(sock_udp_ep_t));
    }
    wolfSSL_SetIORecv(sock->ctx, GNRC_Receive);
    wolfSSL_SetIOSend(sock->ctx, GNRC_SendTo);
    return 0;
}

#ifdef MODULE_SOCK_TCP

void tls_socket_close(sock_tls_t *sk)
{
    sock_tcp_close(&sk->conn.tcp);
    wolfSSL_free(sk->ssl);
}

int sock_tls_accept(WOLFSSL_METHOD *method, sock_tcp_queue_t *queue,
		sock_tls_t **  	sock,
		uint32_t  	timeout ) 	
{
    int ret;
    *sock = gnrc_sock_alloc(method, MODE_TLS);
    if (!*sock)
        return -ENOMEM;
    ret = sock_tcp_accept(queue, &(*sock->conn.tcp));
    if (ret < 0) {
        wolfSSL_Free(*sock->ctx);
        XFREE(*sock);
        *sock = 0;
        return ret;
    }
    *sock->ssl = wolfSSL_new(*sock->ctx);
    wolfSSL_SetIOReadCtx(*sock->ssl, *sock);
    wolfSSL_SetIOWriteCtx(*sock->ssl, *sock);
    ret = wolfSSL_accept(sk->ssl);
    if (ret == SSL_SUCCESS) {
        wolfSSL_set_using_nonblock(sk->ssl, 0);
        return 0;
    } else {
        return ret;
    }
    return 0;
}

int sock_tls_connect(WOLFSSL_METHOD *method, 
        const sock_tcp_ep_t *  	remote,
        sock_tls_t **sock;
		uint16_t  	local_port,
		uint16_t  	flags)
{
    int ret;
    *sock = gnrc_sock_alloc(method, MODE_TLS);
    if (!*sock)
        return -ENOMEM;
    ret = sock_tcp_connect(&(*sock->conn.tcp), remote, local_port, flags);
    if (ret < 0) {
        wolfSSL_Free(*sock->ctx);
        XFREE(*sock);
        *sock = 0;
        return ret;
    }
    *sock->ssl = wolfSSL_new(*sock->ctx);
    wolfSSL_SetIOReadCtx(*sock->ssl, *sock);
    wolfSSL_SetIOWriteCtx(*sock->ssl, *sock);
    ret = wolfSSL_connect(*sock->ssl);
    if (ret == SSL_SUCCESS) {
        wolfSSL_set_using_nonblock(*sock->ssl, 0);
        return 0;
    } else {
        return ret;
    }
    return 0;
}

#endif



#include <ctype.h>
int strncasecmp(const char *s1, const char * s2, unsigned int sz)
{
    for( ; sz>0; sz--)
        if(toupper(s1++) != toupper(s2++))
	    return 1;
    return 0;	
}
