#include <addr_map.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <util.h>
#include <rb.h>

typedef struct {
    __rb_node_t base;
    uint64_t key;
    void* obj;
} __addr_node_t;

typedef struct {
    void* next;
    uint32_t alloc, total;
} __mem_node_t;

typedef struct {
    __addr_node_t header;
    uint64_t size;
    __mem_node_t* mem_list;
    __addr_node_t* free_node_list;
} __addr_map_t;

static __mem_node_t*
__alloc_mem_node()
{
    const int size = 1 << 12;
    void* page =
        mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED)
        return NULL;
    CHECK(__is_addr_aligned(page, 4));
    __mem_node_t* node = page;
    node->next = NULL;
    node->total = (size - sizeof(*node)) / sizeof(__addr_node_t);
    CHECK(node->total * sizeof(__addr_node_t) + sizeof(__mem_node_t) == size);
    return node;
}

static __addr_node_t*
__mem_node_alloc(__mem_node_t* mem_node)
{
    if (mem_node->alloc == mem_node->total)
        return NULL;
    __addr_node_t* nodes = (void*)((char*)mem_node + sizeof(*mem_node));
    __addr_node_t* node = &nodes[mem_node->alloc++];
    return node;
}

static __addr_node_t*
__addr_map_alloc(__addr_map_t* map)
{
    __addr_node_t* node = NULL;
    if (map->free_node_list)
    {
        node = map->free_node_list;
        map->free_node_list = (void*)node->base.right;
        return node;
    }
    if (!map->mem_list)
    {
        map->mem_list = __alloc_mem_node();
        if (!map->mem_list)
            return NULL;
    }
    node = __mem_node_alloc(map->mem_list);
    if (!node)
    {
        __mem_node_t* mem_node = __alloc_mem_node();
        if (!mem_node)
            return NULL;
        mem_node->next = map->mem_list;
        map->mem_list = mem_node;
        node = __mem_node_alloc(map->mem_list);
        CHECK(node);
    }
    return node;
}

void
__addr_map_dealloc(__addr_map_t* map, __addr_node_t* node)
{
    if (node)
    {
        node->base.right = (void*)map->free_node_list;
        map->free_node_list = node;
    }
}

static uint64_t
__hash_addr(uint32_t addr)
{

    return addr;
}

void*
_new_addr_map()
{
    __addr_map_t* map = malloc(sizeof(__addr_map_t));
    if (!map)
        return NULL;
    __rb_init(&map->header.base);
    map->header.key = 0;
    map->header.obj = NULL;
    map->size = 0;
    map->mem_list = NULL;
    map->free_node_list = NULL;
    return map;
}

void
_del_addr_map(void* m)
{
    __addr_map_t* map = m;
    __mem_node_t* list = map->mem_list;
    __mem_node_t* next = NULL;
    for (; list; list = next)
    {
        next = list->next;
        munmap(list, 1 << 12);
    }
    free(m);
}

static __addr_node_t*
__addr_map_find(__addr_map_t* map, uint64_t key)
{
    __addr_node_t* node = (__addr_node_t*)__rb_root(&map->header.base);
    while (node)
    {
        if (key == node->key)
            return node;
        int ret = key > node->key ? -1 : 1;
        if (ret < 0)
            node = (__addr_node_t*)node->base.right;
        else
            node = (__addr_node_t*)node->base.left;
    }
    return NULL;
}

static __addr_node_t*
__addr_map_find_add(__addr_map_t* map, uint64_t key, bool* left)
{
    __addr_node_t* par = &map->header;
    __addr_node_t* node = (__addr_node_t*)__rb_root(&map->header.base);
    int ret;
    while (node)
    {
        if (key == node->key)
            return NULL;
        par = node;
        ret = key > node->key ? -1 : 1;
        if (ret < 0)
            node = (__addr_node_t*)node->base.right;
        else
            node = (__addr_node_t*)node->base.left;
    }
    *left = ret > 0;
    return par;
}

static void
__addr_node_swap(__rb_node_t* n1, __rb_node_t* n2)
{
    __addr_node_t *x = (__addr_node_t*)n1, *y = (__addr_node_t*)n2;
    uint64_t __key;
    void* __o;
    __key = x->key;
    x->key = y->key;
    y->key = __key;
    __o = x->obj;
    x->obj = y->obj;
    y->obj = __o;
}

static void
__addr_node_free(void* args, __rb_node_t* node)
{
    __addr_map_t* map = args;
    __addr_map_dealloc(map, (__addr_node_t*)node);
    --map->size;
}

bool
_addr_map_add(void* m, uint32_t addr, void* o)
{
    if (!o)
        return false;
    __addr_map_t* map = m;
    uint64_t key = __hash_addr(addr);
    bool left;
    __addr_node_t* par = __addr_map_find_add(map, key, &left);
    if (!par)
        return false;
    __addr_node_t* node = __addr_map_alloc(map);
    if (!node)
        return false;
    node->key = key;
    node->obj = o;
    __rb_add(left, (void*)node, (void*)par, &map->header.base);
    ++map->size;
    return true;
}

void*
_addr_map_remove(void* m, uint32_t addr)
{
    __addr_map_t* map = m;
    uint64_t key = __hash_addr(addr);
    __addr_node_t* node = __addr_map_find(map, key);
    if (!node)
        return NULL;
    void* o = node->obj;
    node = (__addr_node_t*)__rb_remove((void*)node,
                                       &map->header.base,
                                       __addr_node_swap);
    __addr_map_dealloc(map, node);
    --map->size;
    return o;
}

void*
_addr_map_get(void* m, uint32_t addr)
{
    __addr_map_t* map = m;
    uint64_t key = __hash_addr(addr);
    __addr_node_t* node = __addr_map_find(map, key);
    if (!node)
        return NULL;
    void* o = node->obj;
    return o;
}

void
_addr_map_clear(void* m)
{
    __addr_map_t* map = m;
    __rb_del(&map->header.base, __addr_node_free, m);
    CHECK(map->size == 0);
}

int
_addr_map_size(void* m)
{
    __addr_map_t* map = m;
    return map->size;
}

__addr_map_iter_t
_addr_map_iter(void* m)
{
    return (__addr_map_iter_t){m, __rb_first(&((__addr_map_t*)m)->header.base)};
}

void
_addr_map_iter_next(__addr_map_iter_t* it)
{
    __addr_map_t* map = it->m;
    it->n = __rb_next(it->n, &map->header.base);
}

void*
_addr_map_iter_value(__addr_map_iter_t* it)
{
    __addr_node_t* node = it->n;
    return node->obj;
}

bool
_addr_map_iter_valid(__addr_map_iter_t* it)
{
    __addr_map_t* map = it->m;
    return it->n != __rb_last(&map->header.base);
}
