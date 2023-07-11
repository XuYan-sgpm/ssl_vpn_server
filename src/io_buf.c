#include <io_buf.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <packet.h>

static const unsigned flag = 0xaabbccdd;

typedef enum
{
    FINISHED = 0,
    SEND,
    RECV
} __io_mode_t;

typedef struct {
    char* mem;
    uint16_t cap, size;
    uint16_t cursor;
    __io_mode_t mode;
} __io_buf_t;

__packet_header_t*
__io_buf_pac_hdr(void* buf)
{
    __io_buf_t* ib = buf;
    if (ib->size == 0 || ib->mode != FINISHED)
        return NULL;
    return (__packet_header_t*)ib->mem;
}

void*
__new_io_buf()
{
    __io_buf_t* ib = malloc(sizeof(__io_buf_t));
    if (!ib)
        return NULL;
    memset(ib, 0, sizeof(*ib));
    if (!__io_buf_reserve(ib, sizeof(__packet_header_t)))
    {
        free(ib);
        return NULL;
    }
    return ib;
}

bool
__io_buf_reserve(void* buf, int len)
{
    __io_buf_t* ib = buf;
    if (ib->cap >= len)
        return true;
    int new_cap = ib->cap << 1;
    new_cap = new_cap < len ? len : new_cap;
    void* new_buf = malloc(new_cap);
    if (!new_buf)
        return false;
    if (ib->mem && ib->size)
        memcpy(new_buf, ib->mem, ib->size);
    free(ib->mem);
    ib->cap = new_cap;
    ib->mem = new_buf;
    return true;
}

void
__del_io_buf(void* buf)
{
    __io_buf_t* ib = buf;
    free(ib->mem);
    free(ib);
}

bool
__io_buf_ready(void* buf)
{
    __io_buf_t* ib = buf;

    return ib->mode == FINISHED && ib->size > 0;
}

static bool
__io_buf_push(__io_buf_t* ib, const void* data, int len)
{
    if (!__io_buf_reserve(ib, ib->size + len))
        return false;
    memcpy(ib->mem + ib->size, data, len);
    ib->size += len;
    return true;
}

static void
__io_buf_check_finished(__io_buf_t* ib)
{
    if (ib->mode == FINISHED)
        return;
    __packet_header_t* hdr = (void*)ib->mem;
    if (hdr->pac_len == ib->size - sizeof(*hdr))
        ib->mode = FINISHED;
}

static int
__io_buf_recv_hdr(__io_buf_t* ib, const void* data, int len)
{
    const char* in = data;
    const char* end = in + len;
    int hdr_rem = sizeof(__packet_header_t) - ib->size;
    int n = hdr_rem > len ? len : hdr_rem;
    if (!__io_buf_push(ib, in, n))
        return -1;
    in += n;
    if (ib->size == sizeof(__packet_header_t))
    {
        __packet_header_t* hdr = (void*)ib->mem;
        if (hdr->pac_flag != flag)
            return -1;
        if (hdr->pac_type < PACKET_IP_DATA && hdr->pac_type >= MAX_PACKET_TYPE)
            return -1;
    }
    return in - (const char*)data;
}

int
__io_buf_recv(void* buf, const void* data, int len)
{
    __io_buf_t* ib = buf;
    if (ib->mode == FINISHED && ib->size > 0)
        return 0;
    if (ib->mode == SEND)
        return -1;
    int n;
    ib->mode = RECV;
    const char* in = data;
    const char* end = in + len;
    if (ib->size < sizeof(__packet_header_t))
    {
        n = __io_buf_recv_hdr(ib, data, len);
        if (n < 0)
            return -1;
        in += n;
    }
    if (in < end)
    {
        __packet_header_t* hdr = (void*)ib->mem;
        n = hdr->pac_len - (ib->size - sizeof(*hdr));
        if (n > len)
            n = len;
        if (!__io_buf_push(ib, in, n))
            return -1;
        in += n;
    }
    __io_buf_check_finished(ib);
    return in - (const char*)data;
}

int
__io_buf_send(void* buf, const void* data, int len, uint16_t type)
{
    __io_buf_t* ib = buf;
    if (ib->mode == FINISHED && ib->size > 0)
        return 0;
    if (ib->mode != FINISHED)
        return -1;
    if (type < PACKET_IP_DATA || type >= MAX_PACKET_TYPE)
        return -1;
    ib->mode = SEND;
    __packet_header_t* hdr = (void*)ib->mem;
    hdr->pac_flag = flag;
    hdr->pac_len = len;
    hdr->pac_type = type;
    ib->size = sizeof(*hdr);
    if (!__io_buf_push(ib, data, len))
    {
        __io_buf_reset(ib);
        return -1;
    }
    ib->mode = FINISHED;
    return len;
}

void
__io_buf_mark(void* buf, int len)
{
    __io_buf_t* ib = buf;
    ib->cursor += len;
}

void*
__io_buf_get(void* buf, int* len, bool raw)
{
    __io_buf_t* ib = buf;
    if (!__io_buf_ready(buf))
        return NULL;
    void* data = ib->mem + ib->cursor;
    *len = ib->size - ib->cursor;
    if (!raw)
    {
        data = (char*)data + sizeof(__packet_header_t);
        *len -= sizeof(__packet_header_t);
    }
    return data;
}

void
__io_buf_reset(void* buf)
{
    __io_buf_t* ib = buf;
    ib->size = 0;
    ib->cursor = 0;
    ib->mode = FINISHED;
}

int
__io_buf_req(void* buf)
{
    __io_buf_t* ib = buf;
    if (ib->size == 0)
        return 0;
    if (ib->size < sizeof(__packet_header_t))
        return sizeof(__packet_header_t) - ib->size;
    __packet_header_t* hdr = (void*)ib->mem;
    if (hdr->pac_len == 0)
        return 0;
    CHECK(ib->size - sizeof(*hdr) <= hdr->pac_len);
    return hdr->pac_len - (ib->size - sizeof(*hdr));
}

bool
__io_buf_empty(void* buf)
{
    __io_buf_t* ib = buf;
    return ib->size == 0;
}

static int
__io_buf_external_recv0(__io_buf_t* ib,
                        int req,
                        int (*read0)(void*, void*, int),
                        void* args,
                        int* err)
{
    int total = 0;
    while (total < req)
    {
        int n = read0(args, ib->mem + ib->size + total, req - total);
        if (n <= 0)
        {
            *err = n;
            break;
        }
        total += n;
    }
    ib->size += total;
    return total;
}

int
__io_buf_recv_ex(void* buf,
                 int (*read0)(void*, void*, int),
                 void* args,
                 int* err)
{
    __io_buf_t* ib = buf;
    if (ib->mode == FINISHED && ib->size > 0)
        return 0;
    if (ib->mode == SEND)
        return -1;
    int n;
    int old = ib->size;
    ib->mode = RECV;
    int hdr_len = sizeof(__packet_header_t);
    if (ib->size < hdr_len)
    {
        n = __io_buf_external_recv0(ib, hdr_len - ib->size, read0, args, err);
        if (ib->size < hdr_len)
            goto __end;
    }
    __packet_header_t* hdr = (void*)ib->mem;
    int total = hdr->pac_len + hdr_len;
    if (!__io_buf_reserve(ib, total))
    {
        __io_buf_reset(ib);
        return -1;
    }
    if (ib->size - hdr_len < hdr->pac_len)
    {
        n = __io_buf_external_recv0(ib,
                                    hdr->pac_len - (ib->size - hdr_len),
                                    read0,
                                    args,
                                    err);
        if (ib->size < hdr_len + hdr->pac_len)
            goto __end;
    }

    ib->mode = FINISHED;
__end:
    return ib->size - old;
}
