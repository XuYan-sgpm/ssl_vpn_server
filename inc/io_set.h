#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    IO_READ = 1,
    IO_WRITE = 2,
    IO_ERR = 4
} __io_event_t;

void*
_new_io_set(int cap);

bool
_io_set_fd(void* s, int fd, __io_event_t ev);

void
_del_io_set(void* s);

void
_io_set_clear(void* s);

int
_io_wait(void* s, int millis);

int
_io_test(void* s, int fd);

int
_io_test_at(void* s, int i);

#ifdef __cplusplus
}
#endif