#include "util.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <arpa/inet.h>
#include <mbedtls/net_sockets.h>
#include <string.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <poll.h>

static pthread_mutex_t _log_mut;

static __attribute__((constructor)) void
__init_log_mut()
{
    pthread_mutex_init(&_log_mut, NULL);
}

bool
__netif_ip(char* ip, int len, const char* name)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    int name_len = strlen(name);
    if (name_len >= (int)sizeof(ifr.ifr_ifrn.ifrn_name))
        return false;
    strcpy(ifr.ifr_ifrn.ifrn_name, name);
    ioctl(fd, SIOCGIFADDR, &ifr);
    const char* host =
        inet_ntoa(((struct sockaddr_in*)&ifr.ifr_ifru.ifru_addr)->sin_addr);
    if ((int)strlen(host) >= len)
        return false;
    strcpy(ip, host);
    return true;
}

int
__create_sock(bool udp)
{
    int fd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    return fd;
}

void
__set_sock_addr(struct sockaddr_in* addr, const char* host, int port)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = inet_addr(host);
}

void
__read_sock_addr(struct sockaddr_in* addr, char* host, int len, int* port)
{
    if (port)
        *port = ntohs(addr->sin_port);
    char _tmp[16] = {0};
    inet_ntop(AF_INET, &addr->sin_addr, _tmp, sizeof(_tmp));
    if (len <= strlen(_tmp))
    {
        __safe_printf("host buffer too small\n");
        return;
    }
    strcpy(host, _tmp);
}

bool
__parse_tun_udp_ip_packet(const void* buf, int len, struct sockaddr_in* addr)
{
    const uint8_t* p = buf;
    int proto_off = 9;
    uint8_t proto = p[proto_off];
    if (proto != 0x11)
        return false;
    int dest_ip_off = 16;
    int dest_port_off = 22;
    addr->sin_family = AF_INET;
    memcpy(&addr->sin_addr, p + dest_ip_off, 4);
    memcpy(&addr->sin_port, p + dest_port_off, 2);
    return true;
}

void
__byte_reverse(const void* data, int data_len, void* out)
{
    const uint8_t* _in = data;
    uint8_t* _out = out;
    for (int i = 0; i < data_len; i++)
    {
        _out[data_len - i - 1] = _in[i];
    }
}

bool
__parse_ip_header(const void* buf, int len, __ip_header_t* header)
{
    if (len < sizeof(*header))
        return false;
    const uint8_t* bytes = buf;
    int off = 0;
    header->version = bytes[0] >> 4;
    header->length = bytes[off++] & 0xf;
    header->service_type = bytes[off++];
    __byte_reverse(bytes + off, 2, &header->msg_len);
    off += 2;
    __byte_reverse(bytes + off, 2, &header->id);
    off += 2;
    uint16_t tmp = *(uint16_t*)(bytes + off);
    header->flag = tmp >> 13;
    header->frag_off = tmp & 0x1fff;
    off += 2;
    header->ttl = bytes[off++];
    header->proto = bytes[off++];
    if (header->proto != 0x11 && header->proto != 0x01 && header->proto != 0x06)
        return false;
    __byte_reverse(bytes + off, 2, &header->check_sum);
    off += 2;
    header->source_ip = *(uint32_t*)(bytes + off);
    off += 4;
    header->dest_ip = *(uint32_t*)(bytes + off);
    off += 4;
    return true;
}

bool
__parse_ip_packet(const void* buf, int len, uint32_t* source, uint32_t* dest)
{
    __ip_header_t header;
    if (!__parse_ip_header(buf, len, &header))
        return false;
    int source_port_off;
    if (header.proto != 0x11 && header.proto != 0x06)
        return false;
    source_port_off = 20;
    if (source)
    {

        *source = header.source_ip;
    }
    if (dest)
    {

        *dest = header.dest_ip;
    }
    return true;
}

bool
__sock_addr_equal(struct sockaddr_in* addr1, struct sockaddr_in* addr2)
{
    return addr1->sin_addr.s_addr == addr2->sin_addr.s_addr
           && addr1->sin_port == addr2->sin_port
           && addr1->sin_family == addr2->sin_family;
}

bool
__sock_bind_netif(int fd, const char* name)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_ifrn.ifrn_name, name);
    int ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    return ret == 0;
}

void
__exec(const char* s, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, s);
    vsprintf(buf, s, args);
    va_end(args);
    strcat(buf, " 2>&1");
    FILE* file = popen(buf, "r");
    if (!file)
        _perror("popen failed");
    __safe_printf("execute command:%s\n", buf);
    while (fgets(buf, sizeof(buf), file))
        __safe_printf("%s", buf);
    int ret = pclose(file);
    if (ret)
        _perror("execute command exit not 0:%d", ret);
}

void
_perror(const char* s, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, s);
    vsprintf(buf, s, args);
    va_end(args);
    __safe_printf("%s\n", buf);
    exit(-1);
}

void
_do_assert(bool pred, const char* file, int line, const char* s)
{
    if (!pred)
    {
        char buf[1024];
        sprintf(buf, "check failed (%s) at %s:%d\n", s, file, line);
        __safe_printf("%s\n", buf);
        exit(-1);
    }
}

void
__print_hex(const void* buf, int len)
{
    pthread_mutex_lock(&_log_mut);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", ((uint8_t*)buf)[i]);
    }
    printf("\n");
    pthread_mutex_unlock(&_log_mut);
}

void
__safe_printf(const char* s, ...)
{
    pthread_mutex_lock(&_log_mut);
    va_list args;
    va_start(args, s);
    vprintf(s, args);
    va_end(args);
    pthread_mutex_unlock(&_log_mut);
}

void
__safe_vprintf(const char* s, va_list args)
{
    pthread_mutex_lock(&_log_mut);
    vprintf(s, args);
    pthread_mutex_unlock(&_log_mut);
}

int
__init_tun(const char* host, char* name)
{

    struct ifreq ifr;
    int fd, err;
    char* clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0)
    {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0)
    {
        close(fd);
        return err;
    }

    __safe_printf("tun name:%s\n", ifr.ifr_ifrn.ifrn_name);
    const char* tun_name = ifr.ifr_ifrn.ifrn_name;

    __exec("sudo ip addr add %s/16 dev %s", host, tun_name);

    __exec("sudo ip link set %s up", tun_name);

    __exec("ifconfig %s", tun_name);
    __safe_printf("Open tun/tap device: %s for reading...\n", tun_name);

    if (name)
        strcpy(name, tun_name);

    return fd;
}

struct timeval
__get_current_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv;
}

static void
__check_timeval(struct timeval* tv)
{
    const int micro_per_sec = 1000000;
    tv->tv_sec += tv->tv_usec / micro_per_sec;
    tv->tv_usec %= micro_per_sec;
}

int
__timeval_compare(struct timeval tv1, struct timeval tv2)
{
    __check_timeval(&tv1);
    __check_timeval(&tv2);
    if (tv1.tv_sec != tv2.tv_sec)
        return tv1.tv_sec < tv2.tv_sec ? -1 : 1;
    if (tv1.tv_usec == tv2.tv_usec)
        return 0;
    return tv1.tv_usec < tv2.tv_usec ? -1 : 1;
}

int64_t
__timeval_diff(struct timeval tv1, struct timeval tv2)
{
    __check_timeval(&tv1);
    __check_timeval(&tv2);
    return (tv1.tv_sec - tv2.tv_sec) * 1000
           + (tv1.tv_usec - tv2.tv_usec) / 1000;
}

bool
__is_addr_aligned(void* p, size_t align)
{
    size_t mask = align - 1;
    uint64_t val = (uint64_t)p;
    return (val & mask) == 0;
}

bool
__init_recursive_lock(pthread_mutex_t* lock)
{
    pthread_mutexattr_t attr;
    bool succ = false;
    if (pthread_mutexattr_init(&attr)
        || pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)
        || pthread_mutex_init(lock, &attr))
        goto __end;
    succ = true;
__end:
    pthread_mutexattr_destroy(&attr);
    return succ;
}
