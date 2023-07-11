#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void*
__new_addr_pool(uint32_t prefix);

void
__del_addr_pool(void* pool);

bool
__addr_pool_alloc(void* pool, uint32_t* addr);

bool
__addr_pool_recycle(void* pool, uint32_t addr);

#ifdef __cplusplus
}
#endif
