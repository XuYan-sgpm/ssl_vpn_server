#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <netinet/in.h>
#include <channel_callback.h>

void*
__new_ssl_io_worker(int i, __channel_callback_t* callback, void* addr_pool);

void
__del_ssl_io_worker(void* w);

bool
__ssl_io_worker_add(void* w, int fd, uint32_t addr);

bool
__ssl_io_worker_post(void* w, int fd, const void* data, int len);

#ifdef __cplusplus
}
#endif
