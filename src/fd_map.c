#include <fd_map.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void* objs[512];
} _fd_map_block_t;

typedef struct {
    _fd_map_block_t** blocks;
    int cap;
} _fd_map_t;

void*
_new_fd_map()
{
    _fd_map_t* map = malloc(sizeof(_fd_map_t));
    if (!map)
        return NULL;
    map->blocks = NULL;
    map->cap = 0;
    return map;
}

void
_del_fd_map(void* m)
{
    _fd_map_t* map = m;
    for (int i = 0; i < map->cap; i++)
    {
        free(map->blocks[i]);
    }
    free(map->blocks);
    free(map);
}

static bool
__realloc_fd_map_blocks(void* m, int req)
{
    _fd_map_t* map = m;
    int cap = map->cap, new_cap;
    if (cap == 0)
    {
        new_cap = req;
    }
    else
    {
        new_cap = cap << 1;
        if (new_cap < req)
            new_cap = req;
    }
    _fd_map_block_t** new_blocks = malloc(new_cap * sizeof(void*));
    if (!new_blocks)
        return false;
    memcpy(new_blocks, map->blocks, map->cap * sizeof(void*));
    memset(new_blocks + map->cap, 0, (new_cap - map->cap) * sizeof(void*));
    free(map->blocks);
    map->blocks = new_blocks;
    map->cap = new_cap;
    return true;
}

static _fd_map_block_t*
__check_fd_map_block(_fd_map_t* map, int i)
{
    _fd_map_block_t* block = map->blocks[i];
    if (block)
        return block;
    block = malloc(sizeof(_fd_map_block_t));
    if (!block)
        return NULL;
    memset(block, 0, sizeof(*block));
    map->blocks[i] = block;
    return block;
}

static void**
__fd_map_find(_fd_map_t* map, int block_idx, int obj_idx)
{
    if (block_idx >= map->cap)
        return NULL;
    _fd_map_block_t* block = map->blocks[block_idx];
    if (!block)
        return NULL;
    return block->objs + obj_idx;
}

static void**
__fd_map_check(_fd_map_t* map, int fd)
{
    int i = fd >> 9;
    int j = fd & 511;
    if (i >= map->cap && !__realloc_fd_map_blocks(map, i + 1))
        return NULL;
    _fd_map_block_t* block = __check_fd_map_block(map, i);
    if (!block)
        return NULL;
    return block->objs + j;
}

bool
_fd_map_add(void* m, int fd, void* o)
{
    if (!o)
        return false;
    _fd_map_t* map = m;
    void** obj_pos = __fd_map_check(map, fd);
    if (!obj_pos)
        return false;
    *obj_pos = o;
    return true;
}

void*
_fd_map_remove(void* m, int fd)
{
    _fd_map_t* map = m;
    void** obj_pos = __fd_map_find(map, fd >> 9, fd & 511);
    if (!obj_pos)
        return NULL;
    void* o = *obj_pos;
    *obj_pos = NULL;
    return o;
}

void*
_fd_map_get(void* m, int fd)
{
    void** obj_pos = __fd_map_find(m, fd >> 9, fd & 511);
    if (!obj_pos)
        return NULL;
    return *obj_pos;
}

void
_fd_map_clear(void* m)
{
    _fd_map_t* map = m;
    for (int i = 0; i < map->cap; i++)
    {
        free(map->blocks[i]);
    }
    memset(map->blocks, 0, map->cap * sizeof(void*));
}
