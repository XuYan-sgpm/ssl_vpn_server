#pragma once

#include <sys/socket.h>
#include <stdbool.h>
#include <channel_callback.h>

#ifdef __cplusplus
extern "C" {
#endif

void*
__new_serv_accepter();

void
__del_serv_accepter(void* a);

void
__serv_accepter_start(void* a);

void
__serv_accepter_register(void* a, __channel_callback_t* channel_callback);

#ifdef __cplusplus
}
#endif
