#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void*
_new_fd_map();

void
_del_fd_map(void* m);

bool
_fd_map_add(void* m, int fd, void* o);

void*
_fd_map_remove(void* m, int fd);

void*
_fd_map_get(void* m, int fd);

void
_fd_map_clear(void* m);

#ifdef __cplusplus
}
#endif