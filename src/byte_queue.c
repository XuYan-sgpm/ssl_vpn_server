#include <byte_queue.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <util.h>

typedef struct {
    char* buf;
    int cap;
    int size;
    pthread_mutex_t mut;
} __byte_queue_t;

static bool
__byte_queue_reserve(void* q, int len)
{
    __byte_queue_t* bq = q;
    int remaining = bq->cap - bq->size;
    if (remaining < len + sizeof(int))
        return false;
    return true;
}

void*
__new_byte_queue(int cap)
{
    if (cap < 0)
        return NULL;
    void* _ptr = malloc(sizeof(__byte_queue_t));
    if (!_ptr)
        return NULL;
    void* buf = malloc(cap);
    if (!buf)
    {
        free(_ptr);
        return NULL;
    }
    __byte_queue_t* bq = _ptr;
    memset(_ptr, 0, sizeof(*bq));
    bq->buf = buf;
    __init_recursive_lock(&bq->mut);
    bq->cap = cap;
    return bq;
}

void
__del_byte_queue(void* q)
{
    __byte_queue_t* bq = q;
    pthread_mutex_destroy(&bq->mut);
    free(bq->buf);
    free(q);
}

int
__byte_queue_offer(void* q, const void* buf, int len)
{
    __byte_queue_t* bq = q;
    int ret = -1;
    pthread_mutex_lock(&bq->mut);
    if (!__byte_queue_reserve(q, len))
    {
        goto end;
    }
    if (len == 0)
    {
        ret = 0;
        goto end;
    }
    char* _start = bq->buf + bq->size;

    *(int*)_start = len;
    _start += sizeof(int);
    memcpy(_start, buf, len);
    bq->size += sizeof(int) + len;
    ret = len;

end:
    pthread_mutex_unlock(&bq->mut);
    return ret;
}

int
__byte_queue_peek(void* q, void* buf, int len)
{
    __byte_queue_t* bq = q;
    int ret;
    pthread_mutex_lock(&bq->mut);
    if (!bq->size)
    {
        ret = 0;
        goto end;
    }
    int _avai = *(int*)bq->buf;
    int _bs = _avai + sizeof(int);
    if (len > _avai)
        len = _avai;
    if (buf)
        memcpy(buf, bq->buf + sizeof(int), len);
    void* _next = bq->buf + _bs;
    memcpy(bq->buf, _next, bq->size - _bs);
    bq->size -= _bs;
    ret = len;

end:
    pthread_mutex_unlock(&bq->mut);
    return ret;
}

int
__byte_queue_peek_ex(void* q, int (*cb)(void*, const void*, int), void* args)
{
    __byte_queue_t* bq = q;
    int ret;
    pthread_mutex_lock(&bq->mut);
    if (!bq->size)
    {
        ret = 0;
        goto __end;
    }
    int _avai = *(int*)bq->buf;
    int _bs = _avai + sizeof(int);
    int off = 0;
    unsigned char* ptr = bq->buf + sizeof(int);
    while (off < _avai)
    {
        int n = cb(args, ptr + off, _avai - off);
        if (n <= 0)
        {
            ret = -1;
            goto __end;
        }
        off += n;
    }
    void* _next = bq->buf + _bs;
    memcpy(bq->buf, _next, bq->size - _bs);
    bq->size -= _bs;
    ret = off;

__end:
    pthread_mutex_unlock(&bq->mut);
    return ret;
}

bool
__byte_queue_empty(void* q)
{
    __byte_queue_t* bq = q;
    pthread_mutex_lock(&bq->mut);
    bool _empty = bq->size == 0;
    pthread_mutex_unlock(&bq->mut);
    return _empty;
}

bool
__byte_queue_offer_if(void* q,
                      const void* buf,
                      int len,
                      bool (*pred)(void*),
                      void* args)
{
    __byte_queue_t* bq = q;
    bool ret = false;
    pthread_mutex_lock(&bq->mut);
    if (!pred(args) || !__byte_queue_reserve(q, len))
    {
        goto end;
    }
    if (len == 0)
    {
        ret = 0;
        goto end;
    }
    bool empty = bq->size == 0;
    char* _start = bq->buf + bq->size;

    *(int*)_start = len;
    _start += sizeof(int);
    memcpy(_start, buf, len);
    bq->size += sizeof(int) + len;
    ret = true;

end:
    pthread_mutex_unlock(&bq->mut);
    return ret;
}
