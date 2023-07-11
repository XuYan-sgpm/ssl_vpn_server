#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __channel_callback __channel_callback_t;

struct __channel_callback {
    void (*on_accept)(__channel_callback_t*, int fd, uint32_t);
    void (*on_handshake)(__channel_callback_t*, uint32_t);
    void (*on_negotiate)(__channel_callback_t*, uint32_t, ...);
    void (*on_data_read)(__channel_callback_t*,
                         uint32_t,
                         const void* data,
                         int len);
    void (*on_idle)(__channel_callback_t*, uint32_t);
    void (*on_resume)(__channel_callback_t*, uint32_t);
    void (*on_closing)(__channel_callback_t*, uint32_t);
    void (*on_removed)(__channel_callback_t*, uint32_t);
};

#ifdef __cplusplus
}
#endif
