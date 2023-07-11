#pragma once

#include <stdbool.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void* const m;
    void* n;
} __addr_map_iter_t;

void*
_new_addr_map();

void
_del_addr_map(void* m);

bool
_addr_map_add(void* m, uint32_t addr, void* o);

void*
_addr_map_remove(void* m, uint32_t addr);

void*
_addr_map_get(void* m, uint32_t addr);

int
_addr_map_size(void* m);

__addr_map_iter_t
_addr_map_iter(void* m);

void
_addr_map_iter_next(__addr_map_iter_t* it);

void*
_addr_map_iter_value(__addr_map_iter_t* it);

bool
_addr_map_iter_valid(__addr_map_iter_t* it);

#ifdef __cplusplus
}
#endif
