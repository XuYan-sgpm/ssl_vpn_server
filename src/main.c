#include <util.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <io_set.h>

#define SERVER_HOST "117.71.57.240"
#define SERVER_PORT 1194

static void*
__send(void* args)
{
    int sock = __create_sock(true);
    CHECK(sock > 0);
    struct sockaddr_in remote;
    __set_sock_addr(&remote, "192.168.22.18", 10240);
    const char* msg = "hello world";
    for (;;)
    {
        int ret =
            sendto(sock, msg, strlen(msg), 0, (void*)&remote, sizeof(remote));
        CHECK(ret > 0);
        sleep(1);
    }
    return NULL;
}

static void
__handle_tun_read(int tun, int stream, struct sockaddr_in* serv)
{
    printf("handle tun read\n");
    char buf[1024];
    int ret = read(tun, buf, sizeof(buf));
    CHECK(ret > 0);
    __print_hex(buf, ret);
    CHECK(sendto(stream, buf, ret, 0, (void*)serv, sizeof(*serv)) == ret);
}

static void
__handle_stream_read(int stream, int tun)
{
    printf("handle stream read\n");
    char buf[1024];
    int ret = recvfrom(stream, buf, sizeof(buf), 0, NULL, NULL);
    CHECK(ret > 0);
    __print_hex(buf, ret);
    CHECK(ret == write(tun, buf, ret));
}

int
main()
{
    char name[16];
    int tun = __init_tun("10.8.0.6", name);
    CHECK(tun > 0);
    __exec("sudo ip link set %s up", name);
    __exec("ifconfig %s", name);
    __exec("sudo route add -net 192.168.22.0/24 dev %s", name);
    __exec("netstat -rn");
    struct sockaddr_in serv;
    __set_sock_addr(&serv, SERVER_HOST, SERVER_PORT);
    int stream = __create_sock(true);
    CHECK(stream > 0);
    int ret = sendto(stream, "hello", 5, 0, (void*)&serv, sizeof(serv));
    CHECK(ret > 0);
    void* s = _new_io_set(2);
    CHECK(s);
    _io_set_fd(s, tun, IO_READ);
    _io_set_fd(s, stream, IO_READ);
    pthread_t th;
    pthread_create(&th, NULL, __send, NULL);
    for (;;)
    {
        int ret = _io_wait(s, -1);
        CHECK(ret > 0);
        int ev = _io_test(s, tun);
        if (ev & IO_READ)
            __handle_tun_read(tun, stream, &serv);
        ev = _io_test(s, stream);
        if (ev & IO_READ)
            __handle_stream_read(stream, tun);
    }
    return 0;
}
