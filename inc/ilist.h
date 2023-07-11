#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void*
_new_ilist();

void
_del_ilist(void* list);

bool
_ilist_push(void* list, int val);

int
_ilist_get(void* list, int i);

bool
_ilist_remove(void* list, int val);

void
_ilist_remove_at(void* list, int i);

int
_ilist_size(void* list);

void
_ilist_clear(void* list);

#ifdef __cplusplus
}
#endif
