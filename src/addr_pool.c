#include <addr_pool.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <util.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

static const uint32_t free_mask = 0xffff;

typedef struct {
    int free_beg, free_end;
    int max_addr_val;
    uint32_t prefix;
    uint16_t* free_list;
    pthread_mutex_t lock;
} __addr_pool_t;

void*
__new_addr_pool(uint32_t prefix)
{
    __addr_pool_t* ap = malloc(sizeof(__addr_pool_t));
    if (!ap)
        return NULL;
    memset(ap, 0, sizeof(*ap));
    void* p = mmap(NULL,
                   32 << 12,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON,
                   -1,
                   0);
    if (p == MAP_FAILED)
        goto __err;
    ap->free_list = p;
    if (!__init_recursive_lock(&ap->lock))
        goto __err;
    ap->prefix = prefix;
    return ap;
__err:
    __del_addr_pool(ap);
}

void
__del_addr_pool(void* pool)
{
    __addr_pool_t* ap = pool;
    if (ap->free_list)
        munmap(ap->free_list, 32 << 12);
    pthread_mutex_destroy(&ap->lock);
    free(ap);
}

bool
__addr_pool_alloc(void* pool, uint32_t* addr)
{
    __addr_pool_t* ap = pool;
    int free_val = -1;
    pthread_mutex_lock(&ap->lock);
    if (ap->free_end - ap->free_beg > 0)
    {
        free_val = ap->free_list[(ap->free_beg++) & free_mask];
        goto __end;
    }
    free_val = ++ap->max_addr_val;
    if (ap->max_addr_val == 0x10000)
    {
        free_val = -1;
        goto __end;
    }
__end:
    pthread_mutex_unlock(&ap->lock);
    if (free_val < 0)
        return false;
    uint32_t addr_val = ap->prefix + free_val;
    uint32_t net_addr;
    __byte_reverse(&addr_val, sizeof(addr_val), &net_addr);
    *addr = net_addr;
    return true;
}

bool
__addr_pool_recycle(void* pool, uint32_t addr)
{
    __addr_pool_t* ap = pool;
    uint32_t addr_val;
    __byte_reverse(&addr, sizeof(addr), &addr_val);
    int free_val = addr_val - ap->prefix;
    if (free_val == 0 || free_val >= 0x10000 || ap->max_addr_val < free_val)
        return false;
    bool succ = false;
    pthread_mutex_lock(&ap->lock);
    if (ap->free_end - ap->free_beg == 0x10000)
        goto __end;
    ap->free_list[(ap->free_end++) & free_mask] = free_val;
    if (ap->free_end - ap->free_beg == 0x10000)
    {
        ap->free_beg = ap->free_end = 0;
        ap->max_addr_val = 0;
    }
    succ = true;
__end:
    pthread_mutex_unlock(&ap->lock);
    return succ;
}
