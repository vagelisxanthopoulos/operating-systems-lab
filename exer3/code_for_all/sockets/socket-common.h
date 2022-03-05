/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT    35001
#define TCP_BACKLOG 5
#define KEY "asu8932jdsfb492"
#define IV "ccak83h23101fghj"
#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE	16  /* AES128 */

ssize_t insist_read(int, void *, size_t);
int fill_urandom_buf(unsigned char *, size_t);
ssize_t insist_write(int, const void *, size_t);
int get_message_stdin(unsigned char *, int);
void enDeCrypt(int, unsigned char*, unsigned char*);
void getorsend(int, int);


#endif /* _SOCKET_COMMON_H */

