#include <rb.h>
#include <gtest/gtest.h>
#include <iostream>
#include <stdlib.h>
#include <util.h>
#include <random>
using namespace std;

struct __int_node {
    __rb_node_t base;
    int i;
};

static __rb_node_t*
__alloc_rb_header()
{
    void* p = aligned_alloc(4, sizeof(__rb_node_t));
    if (!p)
        return NULL;
    CHECK(__is_addr_aligned(p, 4));
    return (__rb_node_t*)p;
}

static __int_node*
__alloc_node(int val)
{
    void* p = aligned_alloc(4, sizeof(__int_node));
    if (!p)
        return NULL;
    CHECK(__is_addr_aligned(p, 4));
    __int_node* node = (__int_node*)p;
    CHECK(__is_addr_aligned(&node->base, 4));
    node->i = val;
    return node;
}

static __rb_node_t*
__find_insert_pos(__rb_node_t* header, int i, bool* left)
{
    __rb_node_t* node = __rb_root(header);
    __rb_node_t* par = header;
    while (node)
    {
        par = node;
        int ret = ((__int_node*)node)->i - i;
        if (ret == 0)
            return NULL;
        *left = ret > 0;
        if (ret < 0)
            node = node->right;
        else
            node = node->left;
    }
    return par;
}

static int
__int_cmp(__rb_node_t* node1, __rb_node_t* node2)
{
    return ((__int_node*)node1)->i - ((__int_node*)node2)->i;
}

static void
__int_swap(__rb_node_t* node1, __rb_node_t* node2)
{
    int tmp;
    tmp = ((__int_node*)node1)->i;
    ((__int_node*)node1)->i = ((__int_node*)node2)->i;
    ((__int_node*)node2)->i = tmp;
}

static __rb_node_t*
__int_clone(void* args, __rb_node_t* node)
{
    __int_node* src = (__int_node*)node;
    __int_node* x = __alloc_node(src->i);
    if (!x)
        return nullptr;
    x->base.parent_color = src->base.parent_color & 1;
    return (__rb_node_t*)x;
}

static void
__int_free(void* args, __rb_node_t* node)
{
    free(node);
}

TEST(rb_test, func1)
{
    __rb_node_t* header = (__rb_node_t*)aligned_alloc(4, sizeof(__rb_node_t));
    __rb_init(header);
    const int n = 10000;
    for (int i = 0; i < n; i++)
    {
        int val = rand();
        bool left;
        __rb_node_t* par = __find_insert_pos(header, val, &left);
        if (!par)
            continue;
        __int_node* node = __alloc_node(i);
        ASSERT_NE(node, nullptr);
        __rb_add(left, &node->base, par, header);
        ASSERT_TRUE(__rb_verify(header, __int_cmp));
    }
    __rb_node_t* h2 = __alloc_rb_header();
    ASSERT_NE(h2, nullptr);
    __rb_init(h2);
    ASSERT_TRUE(__rb_copy(header, __int_clone, nullptr, h2));
    ASSERT_TRUE(__rb_eq(h2, header, __int_cmp));
    __rb_node_t *iter = __rb_first(header), *next;
    while (iter != __rb_last(header))
    {
        next = __rb_next(iter, header);
        free(__rb_remove(iter, header, __int_swap));
        iter = next;
        ASSERT_TRUE(__rb_verify(header, __int_cmp));
    }
    __rb_del(h2, __int_free, nullptr);
}
