#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <channel_callback.h>

typedef struct __serv_channel_callback __serv_channel_callback_t;
struct __serv_channel_callback {
    __channel_callback_t base;
    void* loop;
    __channel_callback_t* usr_cb;
    char ip[16];
};

__channel_callback_t*
__new_serv_channel_cb(__channel_callback_t* cb, void* loop);

void
__del_serv_channel_cb(__channel_callback_t* cb);

#ifdef __cplusplus
}
#endif
