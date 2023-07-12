#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

bool
__netif_ip(char* ip, int len, const char* name);

int
__create_sock(bool udp);

void
__set_sock_addr(struct sockaddr_in* addr, const char* host, int port);

void
__read_sock_addr(struct sockaddr_in* addr, char* host, int len, int* port);

bool
__sock_addr_equal(struct sockaddr_in* addr1, struct sockaddr_in* addr2);

bool
__parse_tun_udp_ip_packet(const void* buf, int len, struct sockaddr_in* addr);

bool
__sock_bind_netif(int fd, const char* name);

void
_perror(const char* s, ...);

void
__exec(const char* s, ...);

void
__print_hex(const void* buf, int len);

void
_do_assert(bool pred, const char* file, int line, const char* s);

#define CHECK(pred) _do_assert((pred), __FILE__, __LINE__, #pred)

void
__print_hex(const void* buf, int len);

int
__init_tun(const char* ip, char* name);

void
__safe_printf(const char* s, ...);

void
__safe_vprintf(const char* s, va_list args);

struct timeval
__get_current_time();

int
__timeval_compare(struct timeval tv1, struct timeval tv2);

int64_t
__timeval_diff(struct timeval tv1, struct timeval tv2);

typedef struct {
    uint8_t version : 4;
    uint8_t length : 4;
    uint8_t service_type;
    uint16_t msg_len;
    uint16_t id;
    uint16_t flag : 3;
    uint16_t frag_off : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check_sum;
    uint32_t source_ip;
    uint32_t dest_ip;
} __ip_header_t;

bool
__parse_ip_packet(const void* buf, int len, uint32_t* source, uint32_t* dest);

bool
__is_addr_aligned(void* p, size_t align);

bool
__init_recursive_lock(pthread_mutex_t* lock);

void
__byte_reverse(const void* data, int data_len, void* out);

#ifdef __cplusplus
}
#endif