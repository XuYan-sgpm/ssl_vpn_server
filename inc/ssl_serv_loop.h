#pragma once

#include <sys/socket.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <channel_callback.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FDS 0xffff

void*
__new_ssl_serv_loop(__channel_callback_t* channel_callback, void* addr_pool);

void
__del_ssl_serv_loop(void* loop);

bool
__ssl_serv_loop_send_ip_packet(void* loop, const void* data, int len);

#ifdef __cplusplus
}
#endif