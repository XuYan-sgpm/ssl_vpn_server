#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void*
__new_byte_queue(int cap);

void
__del_byte_queue(void* queue);

int
__byte_queue_offer(void* q, const void* buf, int len);

bool
__byte_queue_offer_if(void* q,
                      const void* buf,
                      int len,
                      bool (*pred)(void*),
                      void* args);

int
__byte_queue_take(void* q, void* buf, int len);

int
__byte_queue_peek(void* q, void* buf, int len);

int
__byte_queue_peek_ex(void* q, int (*cb)(void*, const void*, int), void* args);

bool
__byte_queue_empty(void* q);

#ifdef __cplusplus
}
#endif