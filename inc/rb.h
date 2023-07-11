#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

typedef struct __rb_node __rb_node_t;
struct __rb_node {
    __rb_node_t *left, *right;
    uint64_t parent_color;
};

void
__rb_init(__rb_node_t* header);

__rb_node_t*
__rb_root(__rb_node_t* header);

void
__rb_add(bool left, __rb_node_t* node, __rb_node_t* par, __rb_node_t* header);

__rb_node_t*
__rb_max(__rb_node_t* header);

__rb_node_t*
__rb_min(__rb_node_t* header);

__rb_node_t*
__rb_remove(__rb_node_t* node,
            __rb_node_t* header,
            void (*__rb_data_swap)(__rb_node_t*, __rb_node_t*));

__rb_node_t*
__rb_first(__rb_node_t* header);

__rb_node_t*
__rb_last(__rb_node_t* header);

__rb_node_t*
__rb_next(__rb_node_t* node, __rb_node_t* header);

__rb_node_t*
__rb_prev(__rb_node_t* node, __rb_node_t* header);

void
__rb_del(__rb_node_t* header,
         void (*__rb_free)(void*, __rb_node_t*),
         void* args);

bool
__rb_copy(__rb_node_t* source_header,
          __rb_node_t* (*__rb_clone)(void*, __rb_node_t*),
          void* args,
          __rb_node_t* header);

bool
__rb_empty(__rb_node_t* header);

bool
__rb_verify(__rb_node_t* header, int (*__rb_cmp)(__rb_node_t*, __rb_node_t*));

bool
__rb_eq(__rb_node_t* header1,
        __rb_node_t* header2,
        int (*__rb_cmp)(__rb_node_t*, __rb_node_t*));

#ifdef __cplusplus
}
#endif