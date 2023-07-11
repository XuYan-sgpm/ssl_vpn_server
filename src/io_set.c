#include <io_set.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

typedef struct {
    struct pollfd* pfds;
    int size;
    int cap;
} _io_set;

void*
_new_io_set(int cap)
{
    _io_set* s = malloc(sizeof(_io_set));
    if (!s)
        return NULL;
    s->pfds = malloc(cap * sizeof(struct pollfd));
    if (!s->pfds)
    {
        free(s);
        return NULL;
    }
    memset(s->pfds, 0, cap * sizeof(struct pollfd));
    s->cap = cap;
    s->size = 0;
    return s;
}

bool
_io_set_fd(void* s, int fd, __io_event_t ev)
{
    _io_set* set = s;
    if (set->size == set->cap)
        return false;
    struct pollfd* pfd = set->pfds + set->size;
    pfd->fd = fd;
    pfd->events = 0;
    pfd->revents = 0;
    if (ev & IO_READ)
        pfd->events |= POLLIN;
    if (ev & IO_WRITE)
        pfd->events |= POLLOUT;
    ++set->size;
    return true;
}

void
_del_io_set(void* s)
{
    _io_set* set = s;
    free(set->pfds);
    free(s);
}

void
_io_set_clear(void* s)
{
    _io_set* set = s;
    set->size = 0;
    memset(set->pfds, 0, set->cap * sizeof(struct pollfd));
}

int
_io_wait(void* s, int millis)
{
    _io_set* set = s;
    int ret = poll(set->pfds, set->size, millis);
    return ret;
}

static struct pollfd*
__io_set_find(_io_set* set, int fd)
{
    for (int i = 0; i < set->size; i++)
    {
        struct pollfd* pfd = set->pfds + i;
        if (pfd->fd == fd)
            return pfd;
    }
    return NULL;
}

int
_io_test(void* s, int fd)
{
    _io_set* set = s;
    struct pollfd* pfd = __io_set_find(set, fd);
    if (!pfd)
    {
        __safe_printf("no pollfd find?\n");
        return -1;
    }
    int ret = 0;
    int events = pfd->revents;
    if (events & POLLIN)
        ret |= IO_READ;
    if (events & POLLOUT)
        ret |= IO_WRITE;
    if (events & (POLLERR | POLLHUP))
        ret |= IO_ERR;
    return ret;
}

int
_io_test_at(void* s, int i)
{
    _io_set* set = s;
    if (i < 0 || i >= set->size)
    {
        __safe_printf("i overflow [%d,%d)", 0, set->size);
        return -1;
    }
    int ret = 0;
    int events = set->pfds[i].revents;
    if (events & POLLIN)
        ret |= IO_READ;
    if (events & POLLOUT)
        ret |= IO_WRITE;
    if (events & (POLLERR | POLLHUP))
        ret |= IO_ERR;
    return ret;
}
