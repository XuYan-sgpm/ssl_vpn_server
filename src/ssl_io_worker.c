#include <ssl_serv_channel.h>
#include <util.h>
#include <string.h>
#include <ssl_serv_loop.h>
#include <errno.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/select.h>
#include <stdlib.h>
#include <byte_queue.h>
#include <unistd.h>
#include <fd_map.h>
#include <ilist.h>
#include <pthread.h>
#include <serv_accepter.h>
#include <io_set.h>
#include <serv_accepter.h>
#include <io_buf.h>
#include <fcntl.h>
#include <addr_pool.h>
#include <packet.h>

typedef enum
{
    HANDSHAKING = 0,
    NEGOTIATE,
    NORMAL,
    IDLE,
    CLOSING,
    DEAD
} __channel_state_t;

typedef enum
{
    ALLOC_IP = 0,
    SEND_IP,
    RECV_IP_ACK
} __negotiate_state_t;

typedef struct {
    __negotiate_state_t nego_state;
    void* addr_pool;
    uint32_t nego_addr;
} __negotiate_params_t;

typedef enum
{
    OK = 0,
    ERR = -1,
    SHOULD_CLOSE = -2,
    WANT_READ = 1,
    WANT_WRITE = 2,
    WANT_READ_WRITE = 3
} __channel_result_t;

typedef struct __attribute__((__aligned__(64))) {
    void* channel;
    void* send_queue;
    void *recv_buf, *send_buf;
    struct timeval check_point;
    int events;
    __channel_state_t state;
    int fd;
    __negotiate_params_t nego_params;
} __channel_ctx_t;

typedef struct {
    void* fd_list;
    void* fd_map;
    pthread_mutex_t fd_lock;
    atomic_bool running;
    pthread_t thread;
    pthread_cond_t not_empty;
    int timeout;
    int max_fds;
    bool waiting;
    int idx;
    uint8_t __heartbeat[3];
    __channel_callback_t* callback;
    void* addr_pool;
} __ssl_io_worker_t;

static void*
__ssl_io_worker_proc(void* args);

static void
__channel_debug(__channel_ctx_t* ctx, const char* s, ...)
{
    char ip[16];
    inet_ntop(AF_INET, &ctx->nego_params.nego_addr, ip, sizeof(ip));
    char format[1024];
    int len = sprintf(format, "channel %s ", ip);
    sprintf(format + len, "%s\n", s);
    va_list _args;
    va_start(_args, s);
    __safe_vprintf(format, _args);
    va_end(_args);
}

static void
__ssl_io_worker_activate_channel(__ssl_io_worker_t* worker,
                                 __channel_ctx_t* ctx)
{
    if (ctx->state == IDLE)
        worker->callback->on_resume(worker->callback,
                                    ctx->nego_params.nego_addr);
    struct timeval now = __get_current_time();
    ctx->check_point = now;
    ctx->check_point.tv_sec += worker->timeout;
    ctx->state = NORMAL;
}

static int
__ssl_io_worker_channel_handshake(__ssl_io_worker_t* worker,
                                  __channel_ctx_t* ctx)
{
    int ret = __ssl_serv_channel_handshake(ctx->channel);
    if (ret == 0)
    {
        worker->callback->on_handshake(worker->callback,
                                       ctx->nego_params.nego_addr);
        return OK;
    }
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        __channel_debug(ctx, "handshake error:%d, remove channel", ret);
        return ERR;
    }

    __channel_debug(ctx, "handshake is not complete, continue");

    return ret == MBEDTLS_ERR_SSL_WANT_READ ? WANT_READ : WANT_WRITE;
}

static int
__ssl_io_worker_flush_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    void* sb = ctx->send_buf;
    if (__io_buf_empty(sb))
    {
        __io_buf_reset(sb);
        goto __end;
    }
    int off = 0, total;
    char* p = __io_buf_get(sb, &total, true);
    CHECK(p && total > 0);
    int ret = OK;
    __channel_debug(ctx, "flush channel");
    __print_hex(p, total);
    while (off < total)
    {
        int n = __ssl_serv_channel_write(ctx->channel, p + off, total - off);
        if (n == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            __io_buf_mark(ctx->send_buf, off);
            ret = WANT_WRITE;
            goto __end;
        }
        if (n <= 0)
        {
            __channel_debug(ctx, "ssl write failed:%d", n);
            ret = ERR;
            break;
        }
        off += n;
    }
    __io_buf_reset(sb);
__end:
    return ret;
}

static int
__ssl_io_worker_check_remote(__ssl_io_worker_t* worker,
                             __channel_ctx_t* ctx,
                             const void* buf,
                             int len)
{
    uint32_t source_addr;
    if (!__parse_ip_packet(buf, len, &source_addr, NULL))
    {
        __channel_debug(ctx, "parse recv ip packet failed");
        return SHOULD_CLOSE;
    }
    if (source_addr != ctx->nego_params.nego_addr)
    {
        char ip[16];

        inet_ntop(AF_INET, &source_addr, ip, sizeof(ip));
        __channel_debug(ctx, "recv ip packet from %s, should not happen", ip);
        return SHOULD_CLOSE;
    }
    return OK;
}

static int
__ssl_io_worker_process_incoming_packet(__ssl_io_worker_t* worker,
                                        __channel_ctx_t* ctx)
{
    int data_len;
    void* data = __io_buf_get(ctx->recv_buf, &data_len, false);
    CHECK(data);
    __packet_header_t* hdr = __io_buf_pac_hdr(ctx->recv_buf);
    switch (hdr->pac_type)
    {
    case PACKET_HEARTBEAT_ACK: {
        __channel_debug(ctx, "receive client heartbeat response");
        return OK;
    }
    case PACKET_IP_ACK: {
        if (ctx->state != NEGOTIATE)
        {
            __channel_debug(ctx, "should not receive ip command ack packet");
            return SHOULD_CLOSE;
        }
        worker->callback->on_negotiate(worker->callback,
                                       ctx->nego_params.nego_addr,
                                       worker->idx,
                                       ctx->fd);
        return OK;
    }
    case PACKET_IP_DATA: {
        int ret = __ssl_io_worker_check_remote(worker, ctx, data, data_len);
        if (ret == OK)
            worker->callback->on_data_read(worker->callback,
                                           ctx->nego_params.nego_addr,
                                           data,
                                           data_len);
        return ret;
    }
    default: {
        __channel_debug(ctx,
                        "should not receive packet which contains type %d",
                        hdr->pac_type);
        return SHOULD_CLOSE;
    }
    }
}

static int
__ssl_io_worker_alloc_ip(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    int ret;
    uint32_t addr;
    if (!__addr_pool_alloc(ctx->nego_params.addr_pool, &addr))
    {
        __safe_printf("alloc addr failed\n");
        return SHOULD_CLOSE;
    }
    char ip[16];
    __safe_printf("alloc addr:%s\n", inet_ntop(AF_INET, &addr, ip, sizeof(ip)));
    ctx->nego_params.nego_addr = addr;
    return OK;
}

static int
__ssl_io_worker_push_ip(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    __io_buf_reset(ctx->send_buf);
    CHECK(__io_buf_send(ctx->send_buf,
                        &ctx->nego_params.nego_addr,
                        sizeof(uint32_t),
                        PACKET_IP_COMMAND)
          > 0);
    return OK;
}

static int
__ssl_io_worker_recv_packet(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    void* recv_buf = ctx->recv_buf;
    CHECK(!__io_buf_ready(recv_buf));
    int err = OK;
    int n =
        __io_buf_recv_ex(recv_buf, __ssl_serv_channel_read, ctx->channel, &err);
    if (n > 0 && __io_buf_ready(recv_buf))
        return OK;
    if (n < 0)
    {
        __channel_debug(ctx, "recv buf internal error");
        return SHOULD_CLOSE;
    }
    if (err == MBEDTLS_ERR_SSL_WANT_READ)
        return WANT_READ;
    return ERR;
}

static int
__ssl_io_worker_do_nego(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    int ret;
    if (ctx->nego_params.nego_state == ALLOC_IP)
    {
        ret = __ssl_io_worker_alloc_ip(worker, ctx);
        if (ret == OK)
            __ssl_io_worker_push_ip(worker, ctx);
    }
    else if (ctx->nego_params.nego_state == SEND_IP)
    {
        ret = __ssl_io_worker_flush_channel(worker, ctx);
    }
    else
    {
        ret = __ssl_io_worker_recv_packet(worker, ctx);
        bool reset = ret != WANT_READ;
        if (ret == OK)
            ret = __ssl_io_worker_process_incoming_packet(worker, ctx);
        if (reset)
            __io_buf_reset(ctx->recv_buf);
    }
    return ret;
}

static int
__ssl_io_worker_negotiate(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    int ret = OK;
    for (;;)
    {
        ret = __ssl_io_worker_do_nego(worker, ctx);
        if (ret != OK || ctx->nego_params.nego_state == RECV_IP_ACK)
            break;
        ctx->nego_params.nego_state++;
    }
    return ret;
}

static int
__ssl_io_worker_read_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{

    void* recv_buf = ctx->recv_buf;
    CHECK(!__io_buf_ready(recv_buf));
    int old = __io_buf_size(recv_buf);
    int n, err = OK;
    bool has_data = false;
    while (err == OK)
    {
        err = __ssl_io_worker_recv_packet(worker, ctx);
        bool reset = err != WANT_READ;
        if (err == OK)
        {
            has_data = true;
            err = __ssl_io_worker_process_incoming_packet(worker, ctx);
        }
        if (reset)
            __io_buf_reset(recv_buf);
    }
    if (!has_data)
    {
        has_data = __io_buf_size(recv_buf) > old;
    }
__end:
    if (has_data && ctx->state <= IDLE)
        __ssl_io_worker_activate_channel(worker, ctx);
    return err;
}

static int
__send_ip_packet(void* args, const void* data, int len)
{
    CHECK(__io_buf_empty(args));
    return __io_buf_send(args, data, len, PACKET_IP_DATA);
}

static int
__ssl_io_worker_write_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    int ret = __ssl_io_worker_flush_channel(worker, ctx);
    if (ret != OK)
        return ret;
    int send_len;
    while (ret == OK)
    {
        send_len = __byte_queue_peek_ex(ctx->send_queue,
                                        __send_ip_packet,
                                        ctx->send_buf);
        if (send_len == 0)
            return OK;
        ret = __ssl_io_worker_flush_channel(worker, ctx);
    }
    return ret;
}

static int
__ssl_io_worker_close_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    int ret = __ssl_serv_channel_close(ctx->channel);
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return WANT_WRITE;
    return ret == 0 ? OK : ERR;
}

static void
__ssl_io_worker_remove_channel(void* w, int fd)
{
    __ssl_io_worker_t* worker = w;
    pthread_mutex_lock(&worker->fd_lock);
    __channel_ctx_t* ctx = _fd_map_remove(worker->fd_map, fd);
    if (!ctx)
        goto __end;
    if (ctx->nego_params.nego_state > ALLOC_IP)
    {
        __channel_debug(ctx, "recycle allocated addr");
        __addr_pool_recycle(worker->addr_pool, ctx->nego_params.nego_addr);
    }
    worker->callback->on_removed(worker->callback, ctx->nego_params.nego_addr);
    _ilist_remove(worker->fd_list, fd);
    close(fd);
    __del_byte_queue(ctx->send_queue);
    __del_ssl_serv_channel(ctx->channel);
    __del_io_buf(ctx->send_buf);
    __del_io_buf(ctx->recv_buf);
    free(ctx);
__end:
    pthread_mutex_unlock(&worker->fd_lock);
}

static void
__ssl_io_worker_handle_err(__ssl_io_worker_t* worker,
                           __channel_ctx_t* ctx,
                           int ret)
{
    if (ret == SHOULD_CLOSE)
    {
        ret = __ssl_io_worker_close_channel(worker, ctx);
        if (ret != OK)
        {
            ctx->state = CLOSING;
            ctx->events = IO_WRITE;
            return;
        }
    }
    __ssl_io_worker_remove_channel(worker, ctx->fd);
}

static void
__ssl_io_worker_handle_ok(__ssl_io_worker_t* worker, __channel_ctx_t* ctx)
{
    switch (ctx->state)
    {
    case HANDSHAKING:
    case NEGOTIATE: {
        ctx->state++;
        ctx->events = 0;
        break;
    }
    case NORMAL:
    case IDLE: {
        ctx->events = IO_READ;
        break;
    }
    case CLOSING: {
        __ssl_io_worker_remove_channel(worker, ctx->fd);
        break;
    }
    }
}

static void
__ssl_io_worker_handle_want_rw(__ssl_io_worker_t* worker,
                               __channel_ctx_t* ctx,
                               int ret)
{
    ctx->events = 0;
    if (ret == WANT_READ || (ctx->state >= NORMAL && ctx->state <= IDLE))
        ctx->events = IO_READ;
    if (ret == WANT_WRITE)
        ctx->events |= IO_WRITE;
}

static void
__ssl_io_worker_check_channel_result(__ssl_io_worker_t* worker,
                                     __channel_ctx_t* ctx,
                                     int ret)
{
    if (ret < 0)
        __ssl_io_worker_handle_err(worker, ctx, ret);
    else if (ret == OK)
        __ssl_io_worker_handle_ok(worker, ctx);
    else
        __ssl_io_worker_handle_want_rw(worker, ctx, ret);
}

static int
__ssl_io_worker_check_channel_activation(__ssl_io_worker_t* worker,
                                         __channel_ctx_t* ctx)
{
    struct timeval now = __get_current_time();
    if (__timeval_compare(ctx->check_point, now) > 0)
        return ctx->state;
    if (ctx->state == IDLE)
    {
        worker->callback->on_closing(worker->callback,
                                     ctx->nego_params.nego_addr);
        return CLOSING;
    }
    CHECK(ctx->state == NORMAL);

    CHECK(__io_buf_send(ctx->send_buf,
                        worker->__heartbeat,
                        sizeof(worker->__heartbeat),
                        PACKET_HEARTBEAT)
          > 0);
    ctx->check_point = now;
    ctx->check_point.tv_sec += 3;
    worker->callback->on_idle(worker->callback, ctx->nego_params.nego_addr);
    return IDLE;
}

static void
__ssl_io_worker_do_channel_events(__ssl_io_worker_t* worker,
                                  __channel_ctx_t* ctx,
                                  int revents)
{
    __channel_state_t state = ctx->state;
    if (!(revents & IO_READ) && state >= NORMAL && state <= IDLE)
    {
        ctx->state = __ssl_io_worker_check_channel_activation(worker, ctx);
        state = ctx->state;
    }
    CHECK(state < DEAD);
    int ret = OK;
    switch (state)
    {
    case HANDSHAKING: {
        ret = __ssl_io_worker_channel_handshake(worker, ctx);
        break;
    }
    case NEGOTIATE: {
        ret = __ssl_io_worker_negotiate(worker, ctx);
        break;
    }
    case NORMAL:
    case IDLE: {
        if (revents & IO_READ)
            ret = __ssl_io_worker_read_channel(worker, ctx);
        if (ret != ERR && ret != SHOULD_CLOSE)
            ret |= __ssl_io_worker_write_channel(worker, ctx);
        break;
    }
    case CLOSING: {
        ret = __ssl_io_worker_close_channel(worker, ctx);
        break;
    }
    case DEAD: {
        __channel_debug(ctx, "state should not be DEAD at here");
        CHECK(ctx->state != DEAD);
    }
    }
    __ssl_io_worker_check_channel_result(worker, ctx, ret);
}

static void
__del_channel_ctx(__channel_ctx_t* ctx)
{
    if (ctx->channel)
        __del_ssl_serv_channel(ctx->channel);
    if (ctx->send_buf)
        __del_io_buf(ctx->send_buf);
    if (ctx->recv_buf)
        __del_io_buf(ctx->recv_buf);
    if (ctx->send_queue)
        __del_byte_queue(ctx->send_queue);
    free(ctx);
}

static __channel_ctx_t*
__ssl_io_worker_new_channel_ctx(__ssl_io_worker_t* worker,
                                int fd,
                                uint32_t addr,
                                int duration)
{
    __channel_ctx_t* ctx = malloc(sizeof(__channel_ctx_t));
    if (!ctx)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->channel = __new_ssl_serv_channel(fd);
    if (!ctx->channel)
        goto __err;
    ctx->send_buf = __new_io_buf();
    if (!ctx->send_buf)
        goto __err;
    ctx->recv_buf = __new_io_buf();
    if (!ctx->recv_buf)
        goto __err;
    ctx->send_queue = __new_byte_queue(64 << 10);
    if (!ctx->send_queue)
        goto __err;
    ctx->events = 0;
    ctx->check_point = __get_current_time();
    ctx->check_point.tv_sec += duration;
    ctx->nego_params.nego_addr = addr;
    ctx->state = HANDSHAKING;
    ctx->nego_params.nego_state = ALLOC_IP;
    ctx->nego_params.addr_pool = worker->addr_pool;
    ctx->fd = fd;
    return ctx;
__err:
    __del_channel_ctx(ctx);
    return NULL;
}

void*
__new_ssl_io_worker(int i, __channel_callback_t* callback, void* addr_pool)
{
    __ssl_io_worker_t* worker = malloc(sizeof(__ssl_io_worker_t));
    if (!worker)
        return NULL;
    memset(worker, 0, sizeof(*worker));
    CHECK(worker->fd_list = _new_ilist());
    CHECK(worker->fd_map = _new_fd_map());
    CHECK(__init_recursive_lock(&worker->fd_lock));
    CHECK(pthread_cond_init(&worker->not_empty, NULL) == 0);
    worker->timeout = 5;
    worker->max_fds = 0xffff;
    worker->waiting = false;
    worker->idx = i;
    worker->callback = callback;
    memset(worker->__heartbeat, 0xff, sizeof(worker->__heartbeat));
    __atomic_store_n(&worker->running, true, __ATOMIC_RELEASE);
    worker->addr_pool = addr_pool;
    CHECK(pthread_create(&worker->thread, NULL, __ssl_io_worker_proc, worker)
          == 0);
    return worker;
}

void
__del_ssl_io_worker(void* w)
{
    __ssl_io_worker_t* worker = w;
    __atomic_store_n(&worker->running, false, __ATOMIC_RELEASE);
    pthread_cond_signal(&worker->not_empty);
    pthread_join(worker->thread, NULL);
    _del_ilist(worker->fd_list);
    _del_fd_map(worker->fd_map);
    pthread_mutex_destroy(&worker->fd_lock);
    pthread_cond_destroy(&worker->not_empty);
    free(w);
}

bool
__ssl_io_worker_add(void* w, int fd, uint32_t addr)
{
    __ssl_io_worker_t* worker = w;
    pthread_mutex_lock(&worker->fd_lock);
    bool succ = false;
    __channel_ctx_t* ctx = _fd_map_get(worker->fd_map, fd);
    if (ctx)
    {
        succ = true;
        goto __end;
    }
    ctx = __ssl_io_worker_new_channel_ctx(worker, fd, addr, worker->timeout);
    if (!ctx)
        goto __end;
    if (!_ilist_push(worker->fd_list, fd))
    {
        __del_channel_ctx(ctx);
        goto __end;
    }
    if (!_fd_map_add(worker->fd_map, fd, ctx))
    {
        _ilist_remove(worker->fd_list, fd);
        __del_channel_ctx(ctx);
        goto __end;
    }
    int flags = fcntl(fd, F_GETFL);
    CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    succ = true;
    __channel_debug(ctx, "established with non-blocking mode");
    bool waiting = worker->waiting;
__end:
    pthread_mutex_unlock(&worker->fd_lock);
    if (succ && waiting)
        pthread_cond_signal(&worker->not_empty);
}

static int
__ssl_io_worker_process_ready_channels0(__ssl_io_worker_t* worker,
                                        __channel_ctx_t** in,
                                        int n,
                                        __channel_ctx_t** out)
{
    int ready_count = 0;
    for (int i = 0; i < n; i++)
    {
        __channel_ctx_t* ctx = in[i];
        if (ctx->events)
            continue;
        __channel_debug(ctx, "channel skip io wait");
        __ssl_io_worker_do_channel_events(worker, ctx, 0);
        if (!ctx->events)
            out[ready_count++] = ctx;
    }
    return ready_count;
}

static void
__ssl_io_worker_process_ready_channels(__ssl_io_worker_t* worker,
                                       __channel_ctx_t** ctx_list,
                                       int n)
{
    __channel_ctx_t* ctx_list1[n];
    __channel_ctx_t* ctx_list2[n];
    __channel_ctx_t **in = ctx_list, **out = ctx_list1;
    n = __ssl_io_worker_process_ready_channels0(worker, in, n, out);
    if (n == 0)
        return;
    in = out;
    out = ctx_list2;
    for (;;)
    {
        n = __ssl_io_worker_process_ready_channels0(worker, in, n, out);
        if (n == 0)
            break;
        __channel_ctx_t** tmp;
        tmp = in;
        in = out;
        out = tmp;
    }
}

static bool
__ssl_io_worker_poll_selected_channels(__ssl_io_worker_t* worker,
                                       __channel_ctx_t** ctx_list,
                                       int n,
                                       void* io_set)
{
    __ssl_io_worker_process_ready_channels(worker, ctx_list, n);
    _io_set_clear(io_set);
    for (int i = 0; i < n; i++)
    {
        __channel_ctx_t* ctx = ctx_list[i];
        _io_set_fd(io_set, ctx->fd, ctx->events);
    }
    int ret = _io_wait(io_set, 1000);
    if (ret < 0)
    {
        __safe_printf("io wait failed:%d\n", errno);
        return false;
    }
    for (int i = 0; i < n; i++)
    {
        int revents = _io_test_at(io_set, i);
        __channel_ctx_t* ctx = ctx_list[i];
        __ssl_io_worker_do_channel_events(worker, ctx, revents);
    }
    return true;
}

static int
__ssl_io_worker_choose(void* w, __channel_ctx_t** ctx_list)
{
    __ssl_io_worker_t* worker = w;
    int i, n = 0;
    for (i = 0; i < _ilist_size(worker->fd_list); i++)
    {
        int fd = _ilist_get(worker->fd_list, i);
        CHECK(fd > 0);
        __channel_ctx_t* ctx = _fd_map_get(worker->fd_map, fd);
        CHECK(ctx->state <= CLOSING && ctx->fd == fd);
        ctx_list[n++] = ctx;
    }
    return n;
}

static int
__ssl_io_worker_prepare(void* w, __channel_ctx_t** ctx_list)
{
    __ssl_io_worker_t* worker = w;
    bool first = true;
    int n = 0;
    pthread_mutex_lock(&worker->fd_lock);
    for (;;)
    {
        if (!__atomic_load_n(&worker->running, __ATOMIC_ACQUIRE))
        {
            __safe_printf("worker receive stop signal, exit wait\n");
            break;
        }
        n = __ssl_io_worker_choose(w, ctx_list);
        if (n > 0)
            break;
        if (first)
        {
            first = false;
            __safe_printf("no fd available, wait\n");
        }
        CHECK(!worker->waiting);
        worker->waiting = true;
        pthread_cond_wait(&worker->not_empty, &worker->fd_lock);
        worker->waiting = false;
    }
    if (n > 0 && !first)
        __safe_printf("client connection comming, wakeup\n");
    pthread_mutex_unlock(&worker->fd_lock);
    return n;
}

static void*
__ssl_io_worker_proc(void* args)
{
    __ssl_io_worker_t* worker = args;
    void* io_set = _new_io_set(worker->max_fds);
    __channel_ctx_t* ctx_list[worker->max_fds];
    while (__atomic_load_n(&worker->running, __ATOMIC_ACQUIRE))
    {
        int n = __ssl_io_worker_prepare(worker, ctx_list);
        if (n <= 0)
        {
            CHECK(!__atomic_load_n(&worker->running, __ATOMIC_ACQUIRE));
            break;
        }
        if (!__ssl_io_worker_poll_selected_channels(worker,
                                                    ctx_list,
                                                    n,
                                                    io_set))
            break;
    }
    _del_io_set(io_set);
    __safe_printf("exit ssl io worker thread %llu\n", pthread_self());
    return NULL;
}

bool
__ssl_io_worker_post(void* w, int fd, const void* data, int len)
{
    __ssl_io_worker_t* worker = w;
    pthread_mutex_lock(&worker->fd_lock);
    bool succ = false;
    __channel_ctx_t* ctx = _fd_map_get(worker->fd_map, fd);
    if (!ctx)
        goto __end;
    succ = __byte_queue_offer(ctx->send_queue, data, len);
__end:
    pthread_mutex_unlock(&worker->fd_lock);
    return succ;
}
