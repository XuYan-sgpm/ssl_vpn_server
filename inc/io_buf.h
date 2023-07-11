#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <packet.h>

#ifdef __cplusplus
extern "C" {
#endif

__packet_header_t*
__io_buf_pac_hdr(void* buf);

void*
__new_io_buf();

bool
__io_buf_reserve(void* buf, int len);

void
__del_io_buf(void* buf);

bool
__io_buf_ready(void* buf);

int
__io_buf_recv(void* buf, const void* data, int len);

int
__io_buf_send(void* buf, const void* data, int len, uint16_t type);

void
__io_buf_mark(void* buf, int len);

void*
__io_buf_get(void* buf, int* len, bool raw);

void
__io_buf_reset(void* buf);

int
__io_buf_req(void* buf);

bool
__io_buf_empty(void* buf);

int
__io_buf_recv_ex(void* buf,
                 int (*read0)(void*, void*, int),
                 void* args,
                 int* err);

int
__io_buf_size(void* buf);

#ifdef __cplusplus
}
#endif
