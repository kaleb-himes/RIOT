
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <net/sock.h>
#include <wolfssl/ssl.h>

#ifndef SOCK_TLS_INCLUDED
#define SOCK_TLS_INCLUDED
#define MODE_TLS 0
#define MODE_DTLS 1

#define MODE_TLS 0
#define MODE_DTLS 1

void sock_dtls_close(sock_tls_t *sk);
void sock_dtls_set_endpoint(sock_tls_t *sk, const sock_udp_ep_t *addr);
ssize_t sock_tls_read(sock_tls_t *sock, void *data, size_t max_len);
ssize_t sock_tls_write(sock_tls_t *sock, const void *data, size_t max_len);
int sock_dtls_create(sock_tls_t *sock, const sock_udp_ep_t *local, const sock_udp_ep_t *remote, uint16_t flags, WOLFSSL_METHOD *method);

#ifdef MODULE_SOCK_TCP
void tls_socket_close(sock_tls_t *sk);
int sock_tls_accept(WOLFSSL_METHOD *method, sock_tcp_queue_t *queue, sock_tls_t **sock, uint32_t timeout);
int sock_tls_connect(WOLFSSL_METHOD *method, const sock_tcp_ep_t *remote, sock_tls_t **sock; uint16_t local_port, uint16_t flags);
#endif

#endif
