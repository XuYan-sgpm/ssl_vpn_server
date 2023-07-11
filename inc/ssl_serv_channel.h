#pragma once

#include <mbedtls/ssl.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void*
__new_ssl_serv_channel(int fd);

void
__del_ssl_serv_channel(void* c);

int
__ssl_serv_channel_read(void* c, void* buf, int len);

int
__ssl_serv_channel_write(void* c, const void* buf, int len);

int
__ssl_serv_channel_handshake(void* c);

int
__ssl_serv_channel_close(void* c);

#ifdef __cplusplus
}
#endif