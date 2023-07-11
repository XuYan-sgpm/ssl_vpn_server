#include <ilist.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int* buf;
    int size;
    int cap;
} _ilist_t;

static bool
__ilist_reserve_at(_ilist_t* ilist, int i, int n)
{
    if (ilist->cap >= ilist->size + n)
    {
        if (i < ilist->size)
        {
            memmove(ilist->buf + i + n,
                    ilist->buf + i,
                    (ilist->size - i) * sizeof(int));
        }
        ilist->size += n;
        return true;
    }
    int new_cap = ilist->cap;
    if (new_cap == 0)
    {
        new_cap = 8;
    }
    else
    {
        new_cap <<= 1;
        if (new_cap < ilist->size + n)
            new_cap = ilist->size + n;
    }
    int* new_buf = malloc(sizeof(int) * new_cap);
    if (!new_buf)
        return false;
    memcpy(new_buf, ilist->buf, i * sizeof(int));
    memcpy(new_buf + i + n, ilist->buf + i, sizeof(int) * (ilist->size - i));
    free(ilist->buf);
    ilist->cap = new_cap;
    ilist->size += n;
    ilist->buf = new_buf;
    return true;
}

static void
__ilist_remove_n(_ilist_t* ilist, int pos, int n)
{
    if (pos + n < ilist->size)
    {
        memcpy(ilist->buf + pos,
               ilist->buf + pos + n,
               sizeof(int) * (ilist->size - pos - n));
    }
    ilist->size -= n;
}

void*
_new_ilist()
{
    _ilist_t* ilist = malloc(sizeof(_ilist_t));
    if (!ilist)
        return NULL;
    memset(ilist, 0, sizeof(*ilist));
    return ilist;
}

void
_del_ilist(void* list)
{
    _ilist_t* ilist = list;
    free(ilist->buf);
    free(ilist);
}

bool
_ilist_push(void* list, int val)
{
    _ilist_t* ilist = list;
    int pos = ilist->size;
    if (!__ilist_reserve_at(list, ilist->size, 1))
        return false;
    ilist->buf[pos] = val;
    return true;
}

int
_ilist_get(void* list, int i)
{
    return ((_ilist_t*)list)->buf[i];
}

bool
_ilist_remove(void* list, int val)
{
    _ilist_t* ilist = list;
    for (int i = 0; i < ilist->size; i++)
    {
        if (ilist->buf[i] == val)
        {
            __ilist_remove_n(ilist, i, 1);
            return true;
        }
    }
    return false;
}

void
_ilist_remove_at(void* list, int i)
{
    __ilist_remove_n(((_ilist_t*)list), i, 1);
}

int
_ilist_size(void* list)
{
    return ((_ilist_t*)list)->size;
}

void
_ilist_clear(void* list)
{
    ((_ilist_t*)list)->size = 0;
}
