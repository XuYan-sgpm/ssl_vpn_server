#pragma once

#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <channel_callback.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    HANDSHAKING = 0,
    NEGOTIATE,
    NORMAL,
    IDLE,
    CLOSING,
    UNAVAILABLE
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
__channel_debug(__channel_ctx_t* ctx, const char* s, ...);

static uint32_t
__channel_addr(__channel_ctx_t* ctx);

static void
__ssl_io_worker_update_channel_checkpoint(__ssl_io_worker_t* worker,
                                          __channel_ctx_t* ctx);

static int
__ssl_io_worker_channel_handshake(__ssl_io_worker_t* worker,
                                  __channel_ctx_t* ctx);

static int
__ssl_io_worker_flush_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__ssl_io_worker_check_remote(__ssl_io_worker_t* worker,
                             __channel_ctx_t* ctx,
                             const void* buf,
                             int len);

static int
__ssl_io_worker_process_incoming_packet(__ssl_io_worker_t* worker,
                                        __channel_ctx_t* ctx);

static int
__ssl_io_worker_alloc_ip(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__ssl_io_worker_push_ip(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__ssl_io_worker_recv_packet(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__ssl_io_worker_do_nego(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__ssl_io_worker_negotiate(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__ssl_io_worker_read_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__send_ip_packet(void* args, const void* data, int len);

static int
__ssl_io_worker_write_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static int
__ssl_io_worker_write_channel(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static void
__ssl_io_worker_remove_channel(void* w, int fd);

static bool
__ssl_io_worker_handle_err(__ssl_io_worker_t* worker,
                           __channel_ctx_t* ctx,
                           int ret);

static bool
__ssl_io_worker_handle_ok(__ssl_io_worker_t* worker, __channel_ctx_t* ctx);

static bool
__ssl_io_worker_handle_want_rw(__ssl_io_worker_t* worker,
                               __channel_ctx_t* ctx,
                               int ret);

static bool
__ssl_io_worker_check_channel_result(__ssl_io_worker_t* worker,
                                     __channel_ctx_t* ctx,
                                     int ret);

static int
__ssl_io_worker_check_channel_timeout(__ssl_io_worker_t* worker,
                                      __channel_ctx_t* ctx);

static bool
__ssl_io_worker_do_channel_events(__ssl_io_worker_t* worker,
                                  __channel_ctx_t* ctx,
                                  int revents);

static void
__del_channel_ctx(__channel_ctx_t* ctx);

static __channel_ctx_t*
__ssl_io_worker_new_channel_ctx(__ssl_io_worker_t* worker,
                                int fd,
                                uint32_t addr);

void*
__new_ssl_io_worker(int i, __channel_callback_t* callback, void* addr_pool);

void
__del_ssl_io_worker(void* w);

bool
__ssl_io_worker_add(void* w, int fd, uint32_t addr);

static int
__ssl_io_worker_process_eventless_channels(__ssl_io_worker_t* worker,
                                        __channel_ctx_t** in,
                                        int n);

static bool
__ssl_io_worker_poll_selected_channels(__ssl_io_worker_t* worker,
                                       __channel_ctx_t** ctx_list,
                                       int n,
                                       void* io_set);

static int
__ssl_io_worker_choose(void* w, __channel_ctx_t** ctx_list);

static int
__ssl_io_worker_prepare(void* w, __channel_ctx_t** ctx_list);

bool
__ssl_io_worker_post(void* w, int fd, const void* data, int len);

#ifdef __cplusplus
}
#endif
