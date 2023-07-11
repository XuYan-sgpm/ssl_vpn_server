#include <serv_accepter.h>
#include <pthread.h>
#include <util.h>
#include <errno.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>

typedef struct {
    pthread_t worker;
    int listen_fd;
    __channel_callback_t* channel_callback;
    atomic_bool stop;
} __serv_accepter_t;

static int
__create_tcp_serv_sock()
{
    int fd = __create_sock(false);
    CHECK(fd > 0);
    int opt = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt))
          == 0);
    char local_ip[16];
    CHECK(__netif_ip(local_ip, sizeof(local_ip), "ens192"));
    __safe_printf("local ip:%s\n", local_ip);
    struct sockaddr_in local;
    __set_sock_addr(&local, local_ip, 1194);
    CHECK(bind(fd, (void*)&local, sizeof(local)) == 0);
    CHECK(listen(fd, 5) == 0);
    int flags = fcntl(fd, F_GETFL);
    CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    return fd;
}

static bool
__serv_accept(void* a)
{
    __serv_accepter_t* sa = a;
    struct pollfd pfd;
    pfd.fd = sa->listen_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int ret = poll(&pfd, 1, 1500);
    if (ret < 0)
    {
        __safe_printf("poll failed:%d\n", errno);
        return false;
    }
    if (ret == 0)
        return true;
    if (!(pfd.revents & POLLIN))
    {
        __safe_printf("listen_fd has error events\n");
        return false;
    }
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    int fd = accept(sa->listen_fd, (void*)&client, &client_len);
    if (fd < 0)
    {
        __safe_printf("accept failed:%d\n", errno);
        return true;
    }
    sa->channel_callback->on_accept(sa->channel_callback,
                                    fd,
                                    client.sin_addr.s_addr);
    return true;
}

void*
__new_serv_accepter()
{
    __serv_accepter_t* sa = malloc(sizeof(__serv_accepter_t));
    if (!sa)
        return NULL;
    memset(sa, 0, sizeof(*sa));
    sa->listen_fd = __create_tcp_serv_sock();
    __atomic_store_n(&sa->stop, false, __ATOMIC_RELEASE);
    return sa;
}

void
__del_serv_accepter(void* a)
{
    __serv_accepter_t* sa = a;
    __atomic_store_n(&sa->stop, true, __ATOMIC_RELEASE);
    close(sa->listen_fd);
    pthread_join(sa->worker, NULL);
    free(sa);
}

void
__serv_accepter_register(void* a, __channel_callback_t* channel_callback)
{
    __serv_accepter_t* sa = a;
    sa->channel_callback = channel_callback;
}

void*
__accept_proc(void* args)
{
    __serv_accepter_t* sa = args;
    while (!__atomic_load_n(&sa->stop, __ATOMIC_ACQUIRE))
    {
        if (!__serv_accept(sa))
            break;
    }
    __safe_printf("exit accept proc\n");
    close(sa->listen_fd);
    return NULL;
}

void
__serv_accepter_start(void* a)
{
    __serv_accepter_t* sa = a;
    CHECK(pthread_create(&sa->worker, NULL, __accept_proc, sa) == 0);
}
