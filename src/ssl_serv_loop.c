#include <util.h>
#include <string.h>
#include <ssl_serv_loop.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <serv_accepter.h>
#include <ssl_io_worker.h>
#include <addr_map.h>
#include <pthread.h>
#include <serv_channel_callback.h>
#include <stdatomic.h>
#include <addr_pool.h>

typedef struct {
    void* accepter;
    void* workers[4];
    uint32_t worker_iter;
    void* addr_map;
    pthread_mutex_t addr_lock;
    __channel_callback_t* serv_channel_callback;
} __ssl_serv_loop_t;

typedef union
{
    struct {
        uint32_t worker_idx;
        uint32_t fd;
    };
    uint64_t data;
} __addr_cache_t;

void
__ssl_serv_loop_new_addr(void* loop, uint32_t addr, int i, int fd)
{
    __ssl_serv_loop_t* sl = loop;
    pthread_mutex_lock(&sl->addr_lock);
    __addr_cache_t cache;
    cache.data = 0;
    cache.worker_idx = i;
    cache.fd = fd;
    _addr_map_add(sl->addr_map, addr, (void*)cache.data);
    pthread_mutex_unlock(&sl->addr_lock);
}

static __addr_cache_t
__ssl_serv_loop_addr_cache(__ssl_serv_loop_t* sl, uint32_t addr)
{
    pthread_mutex_lock(&sl->addr_lock);
    __addr_cache_t cache;
    cache.data = 0;
    void* o = _addr_map_get(sl->addr_map, addr);
    if (!o)
        goto __end;
    cache.data = (uint64_t)o;
__end:
    pthread_mutex_unlock(&sl->addr_lock);
    return cache;
}

void
__ssl_serv_loop_remove_addr(void* loop, uint32_t addr)
{
    __ssl_serv_loop_t* sl = loop;
    pthread_mutex_lock(&sl->addr_lock);
    void* o = _addr_map_remove(sl->addr_map, addr);

    pthread_mutex_unlock(&sl->addr_lock);
}

void
__ssl_serv_loop_accept_new_conn(void* loop, int fd, uint32_t addr)
{
    __ssl_serv_loop_t* sl = loop;

    int num_workers = sizeof(sl->workers) / sizeof(void*);
    int i = (sl->worker_iter++) % num_workers;

    __ssl_io_worker_add(sl->workers[i], fd, addr);
}

void*
__new_ssl_serv_loop(__channel_callback_t* channel_callback, void* addr_pool)
{
    __ssl_serv_loop_t* sl = malloc(sizeof(__ssl_serv_loop_t));
    if (!sl)
        return NULL;
    memset(sl, 0, sizeof(*sl));
    if (!__init_recursive_lock(&sl->addr_lock))
        goto __err;
    sl->addr_map = _new_addr_map();
    if (!sl->addr_map)
        goto __err;
    sl->accepter = __new_serv_accepter();
    if (!sl->accepter)
        goto __err;
    __channel_callback_t* cb = __new_serv_channel_cb(channel_callback, sl);
    if (!cb)
        goto __err;
    sl->serv_channel_callback = cb;
    for (int i = 0; i < sizeof(sl->workers) / sizeof(void*); i++)
    {
        sl->workers[i] = __new_ssl_io_worker(i, cb, addr_pool);
        if (!sl->workers[i])
            goto __err;
    }
    __serv_accepter_register(sl->accepter, cb);
    __serv_accepter_start(sl->accepter);
    return sl;
__err:
    __del_ssl_serv_loop(sl);
    return NULL;
}

void
__del_ssl_serv_loop(void* loop)
{
    __ssl_serv_loop_t* sl = loop;
    pthread_mutex_destroy(&sl->addr_lock);
    if (sl->accepter)
        __del_serv_accepter(sl->accepter);
    for (int i = 0; i < sizeof(sl->workers) / sizeof(void*); i++)
        __del_ssl_io_worker(sl->workers[i]);
    if (sl->addr_map)
        _del_addr_map(sl->addr_map);
    if (sl->serv_channel_callback)
        __del_serv_channel_cb(sl->serv_channel_callback);
    free(loop);
}

bool
__ssl_serv_loop_send_ip_packet(void* loop, const void* data, int len)
{
    uint32_t dest;
    if (!__parse_ip_packet(data, len, NULL, &dest))
    {
        __safe_printf("parse ip packet failed\n");
        return false;
    }
    __ssl_serv_loop_t* sl = loop;
    __addr_cache_t cache = __ssl_serv_loop_addr_cache(sl, dest);
    if (!cache.data)
        goto __err;
    if (!__ssl_io_worker_post(sl->workers[cache.worker_idx],
                              cache.fd,
                              data,
                              len))
        goto __err;
    return true;
__err : {
    char ip[16];

    inet_ntop(AF_INET, &dest, ip, sizeof(ip));
    __safe_printf("channel %s not found\n", ip);
}
    return false;
}
