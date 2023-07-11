#include <ssl_serv_loop.h>
#include <util.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <channel_callback.h>
#include <stdlib.h>
#include <addr_pool.h>

static int tun;

static void
__usr_on_recv(__channel_callback_t* cb, uint32_t addr, const void* buf, int len)
{
    char ip[16];
    // __read_sock_addr(&addr, ip, sizeof(ip), NULL);
    inet_ntop(AF_INET, &addr, ip, sizeof(ip));
    __safe_printf("read from %s,%d, ", ip, len);
    __print_hex(buf, len);
    if (len == write(tun, buf, len))
    {
        __safe_printf("write tun successfully\n");
        return;
    }
    __safe_printf("write tun failed:%d,%d\n", len, errno);
}

static void
__usr_on_accept(__channel_callback_t* cb, int fd, uint32_t addr)
{
    char client_ip[16];
    // int client_port;
    // __read_sock_addr(&addr, client_ip, sizeof(client_ip), &client_port);
    inet_ntop(AF_INET, &addr, client_ip, sizeof(client_ip));
    __safe_printf("remote client %s\n", client_ip);
    // __ssl_serv_loop_register_recv_callback(loop, fd, __recv_cb, &tun);
}

__channel_callback_t*
__new_usr_channel_callback()
{
    void* p = malloc(sizeof(__channel_callback_t));
    if (!p)
        return NULL;
    __channel_callback_t* cb = p;
    memset(cb, 0, sizeof(*cb));
    cb->on_accept = __usr_on_accept;
    cb->on_data_read = __usr_on_recv;
    return cb;
}

static void
__listen_tun_read(int tun, void* loop)
{
    char buf[1024];
    for (;;)
    {
        int ret = read(tun, buf, sizeof(buf));
        if (ret < 0)
            _perror("read from tun failed:%d", errno);
        __safe_printf("\nread from tun: ");
        __print_hex(buf, ret);
        __safe_printf("send to ssl serv loop...");
        bool succ = __ssl_serv_loop_send_ip_packet(loop, buf, ret);
        if (succ)
            __safe_printf("success\n");
        else
            __safe_printf("failed\n");
    }
}

int
main()
{
    __channel_callback_t* cb = __new_usr_channel_callback();
    if (!cb)
        _perror("new usr channel callback failed\n");
    void* addr_pool = __new_addr_pool(0x0a080000);
    if (!addr_pool)
        _perror("new addr pool failed");

    uint32_t addr;
    if (!__addr_pool_alloc(addr_pool, &addr))
        _perror("alloc addr failed");

    char tun_ip[16];

    char tun_name[10] = {0};
    tun =
        __init_tun(inet_ntop(AF_INET, &addr, tun_ip, sizeof(tun_ip)), tun_name);
    if (tun < 0)
        _perror("init %s failed:%d", tun_name, errno);

    void* loop = __new_ssl_serv_loop(cb, addr_pool);
    CHECK(loop);
    __listen_tun_read(tun, loop);
    return 0;
}