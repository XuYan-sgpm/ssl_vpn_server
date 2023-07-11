#include <serv_channel_callback.h>
#include <ssl_serv_loop.h>
#include <ssl_io_worker.h>
#include <util.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static void
__parse_addr(__serv_channel_callback_t* scb, uint32_t addr)
{
    inet_ntop(AF_INET, &addr, scb->ip, sizeof(scb->ip));
}

void
__ssl_serv_loop_accept_new_conn(void* loop, int fd, uint32_t addr);

void
__ssl_serv_loop_new_addr(void* loop, uint32_t addr, int i, int fd);

void
__ssl_serv_loop_remove_addr(void* loop, uint32_t addr);

static void
__serv_on_accept(__channel_callback_t* cb, int fd, uint32_t addr)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("on accept, fd:%d, addr:%s\n", fd, scb->ip);
    __ssl_serv_loop_accept_new_conn(scb->loop, fd, addr);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_accept)
        usr->on_accept(usr, fd, addr);
}

static void
__serv_on_handshake(__channel_callback_t* cb, uint32_t addr)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("channel [%s] handshake successfully\n", scb->ip);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_handshake)
        usr->on_handshake(usr, addr);
}

static void
__serv_on_negotiate(__channel_callback_t* cb, uint32_t addr, ...)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("negotiated ip: %s\n", scb->ip);
    va_list args;
    va_start(args, addr);
    int worker_idx = va_arg(args, int);
    int fd = va_arg(args, int);
    __ssl_serv_loop_new_addr(scb->loop, addr, worker_idx, fd);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_negotiate)
        usr->on_negotiate(usr, addr);
}

static void
__serv_on_data_read(__channel_callback_t* cb,
                    uint32_t addr,
                    const void* data,
                    int len)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("receive from channel %s\n", scb->ip);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_data_read)
        usr->on_data_read(usr, addr, data, len);
}

static void
__serv_on_idle(__channel_callback_t* cb, uint32_t addr)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("channel %s is idle, send heartbeat\n", scb->ip);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_idle)
        usr->on_idle(usr, addr);
}

static void
__serv_on_resume(__channel_callback_t* cb, uint32_t addr)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("channel %s is active\n", scb->ip);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_resume)
        usr->on_resume(usr, addr);
}

static void
__serv_on_closing(__channel_callback_t* cb, uint32_t addr)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("closing channel %s\n", scb->ip);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_closing)
        usr->on_closing(usr, addr);
}

static void
__serv_on_removed(__channel_callback_t* cb, uint32_t addr)
{
    __serv_channel_callback_t* scb = (void*)cb;
    __parse_addr(scb, addr);
    __safe_printf("channel %s is removed\n", scb->ip);
    __ssl_serv_loop_remove_addr(scb->loop, addr);
    __channel_callback_t* usr = scb->usr_cb;
    if (usr->on_removed)
        usr->on_removed(usr, addr);
}

__channel_callback_t*
__new_serv_channel_cb(__channel_callback_t* cb, void* loop)
{
    void* p = malloc(sizeof(__serv_channel_callback_t));
    if (!p)
        return NULL;
    memset(p, 0, sizeof(__serv_channel_callback_t));
    __serv_channel_callback_t* scb = p;
    scb->usr_cb = cb;
    scb->loop = loop;
    scb->base.on_accept = __serv_on_accept;
    scb->base.on_handshake = __serv_on_handshake;
    scb->base.on_negotiate = __serv_on_negotiate;
    scb->base.on_data_read = __serv_on_data_read;
    scb->base.on_idle = __serv_on_idle;
    scb->base.on_resume = __serv_on_resume;
    scb->base.on_closing = __serv_on_closing;
    scb->base.on_removed = __serv_on_removed;
    return p;
}

void
__del_serv_channel_cb(__channel_callback_t* cb)
{
    free(cb);
}
