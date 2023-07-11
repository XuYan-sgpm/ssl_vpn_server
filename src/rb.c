#include <rb.h>
#include <stddef.h>

typedef enum
{
    RED = 0,
    BLACK
} __color_t;

static inline __rb_node_t*
__parent(__rb_node_t* node)
{
    return (__rb_node_t*)((node->parent_color >> 2) << 2);
}

static inline void
__set_parent(__rb_node_t* node, __rb_node_t* parent)
{
    // CHECK((uint64_t)parent & 3 == 0);
    __color_t color = node->parent_color & 1;
    node->parent_color = ((uint64_t)parent >> 2) << 2;
    node->parent_color |= color;
}

static inline __color_t
__color(__rb_node_t* node)
{
    return node->parent_color & 1;
}

static inline void
__set_color(__rb_node_t* node, __color_t color)
{
    node->parent_color =
        color ? (node->parent_color | 1) : (node->parent_color & ~1ull);
}

static void
__left_rotate(__rb_node_t* node, __rb_node_t* header)
{
    __rb_node_t *r, *rl;
    r = node->right;
    rl = r->left;
    node->right = rl;
    if (rl)
        __set_parent(rl, node);
    __rb_node_t* par = __parent(node);
    if (par == header)
        __set_parent(header, r);
    else if (node == par->left)
        par->left = r;
    else
        par->right = r;
    __set_parent(r, par);
    r->left = node;
    __set_parent(node, r);
}

static void
__right_rotate(__rb_node_t* node, __rb_node_t* header)
{
    __rb_node_t *l, *lr;
    l = node->left;
    lr = l->right;
    node->left = lr;
    if (lr)
        __set_parent(lr, node);
    __rb_node_t* par = __parent(node);
    if (par == header)
        __set_parent(header, l);
    else if (par->left == node)
        par->left = l;
    else
        par->right = l;
    __set_parent(l, par);
    l->right = node;
    __set_parent(node, l);
}

static void
__add_rebalance(__rb_node_t* node, __rb_node_t* header)
{
    __set_color(node, RED);
    __rb_node_t* par;
    while (__color((par = __parent(node))) == RED && par != header)
    {
        __rb_node_t* grand = __parent(par);
        bool left = par->left == node;
        __rb_node_t* uncle = par == grand->left ? grand->right : grand->left;
        if (uncle && __color(uncle) == RED)
        {
            __set_color(uncle, BLACK);
            __set_color(par, BLACK);
            __set_color(grand, RED);
            node = grand;
            continue;
        }
        if (left != (par == grand->left))
        {
            left ? __right_rotate(par, header) : __left_rotate(par, header);
            node = par;
            par = __parent(node);
        }
        if (par == grand->left)
            __right_rotate(grand, header);
        else
            __left_rotate(grand, header);
        __set_color(par, BLACK);
        __set_color(grand, RED);
        break;
    }
    __set_color(__parent(header), BLACK);
}

static void
__remove_rebalance(__rb_node_t* node, __rb_node_t* par, __rb_node_t* header)
{
    while ((!node || __color(node) == BLACK) && par != header)
    {
        bool left = node == par->left;
        __rb_node_t* cousin = left ? par->right : par->left;
        if (__color(cousin) == RED)
        {
            __set_color(cousin, BLACK);
            __set_color(par, RED);
            left ? __left_rotate(par, header) : __right_rotate(par, header);
            cousin = left ? par->right : par->left;
        }
        if ((!cousin->left || __color(cousin->left) == BLACK)
            && (!cousin->right || __color(cousin->right) == BLACK))
        {
            __set_color(cousin, RED);
            node = par;
            par = __parent(node);
            continue;
        }
        if (left && (!cousin->right || __color(cousin->right) == BLACK))
        {
            __set_color(cousin->left, BLACK);
            __set_color(cousin, RED);
            __right_rotate(cousin, header);
            cousin = par->right;
        }
        else if (!left && (!cousin->left || __color(cousin->left) == BLACK))
        {
            __set_color(cousin->right, BLACK);
            __set_color(cousin, RED);
            __left_rotate(cousin, header);
            cousin = par->left;
        }
        __set_color(cousin, __color(par));
        __set_color(par, BLACK);
        if (left)
        {
            __set_color(cousin->right, BLACK);
            __left_rotate(par, header);
        }
        else
        {
            __set_color(cousin->left, BLACK);
            __right_rotate(par, header);
        }
        break;
    }
    if (node)
        __set_color(node, BLACK);
}

void
__rb_init(__rb_node_t* header)
{
    header->parent_color = 0;
    header->left = header->right = header;
}

__rb_node_t*
__rb_root(__rb_node_t* header)
{
    return __parent(header);
}

static __rb_node_t*
__rb_right_most(__rb_node_t* node)
{
    while (node->right)
        node = node->right;
    return node;
}

static __rb_node_t*
__rb_left_most(__rb_node_t* node)
{
    while (node->left)
        node = node->left;
    return node;
}

__rb_node_t*
__rb_max(__rb_node_t* header)
{
    return header->left;
}

__rb_node_t*
__rb_min(__rb_node_t* header)
{
    return header->right;
}

void
__rb_add(bool left, __rb_node_t* node, __rb_node_t* par, __rb_node_t* header)
{
    node->left = node->right = NULL;
    __set_parent(node, par);
    if (par == header)
    {
        __set_parent(header, node);
        header->left = node;
        header->right = node;
        __set_color(node, BLACK);
        return;
    }
    if (left)
    {
        par->left = node;
        if (par == header->left)
            header->left = node;
    }
    else
    {
        par->right = node;
        if (par == header->right)
            header->right = node;
    }
    __add_rebalance(node, header);
}

__rb_node_t*
__rb_remove(__rb_node_t* node,
            __rb_node_t* header,
            void (*__rb_data_swap)(__rb_node_t*, __rb_node_t*))
{
    __rb_node_t *__x, *__y, *__x_par;
    __x = node;
    if (!node->left)
    {
        __y = node->right;
    }
    else if (!node->right)
    {
        __y = node->left;
    }
    else
    {
        __x = __rb_right_most(node->left);
        __y = __x->left;
    }
    __x_par = __parent(__x);
    if (__x != node)
        __rb_data_swap(__x, node);
    if (header == __x_par)
        __set_parent(header, __y);
    else if (__x == __x_par->left)
        __x_par->left = __y;
    else
        __x_par->right = __y;
    if (__y)
        __set_parent(__y, __x_par);
    if (__x == header->left)
        header->left = __y ? __rb_left_most(__y) : __x_par;
    if (__x == header->right)
        header->right = __y ? __rb_right_most(__y) : __x_par;
    if (__color(__x) == BLACK)
        __remove_rebalance(__y, __x_par, header);
    return __x;
}

__rb_node_t*
__rb_first(__rb_node_t* header)
{
    return header->left;
}

__rb_node_t*
__rb_last(__rb_node_t* header)
{
    return header;
}

__rb_node_t*
__rb_next(__rb_node_t* node, __rb_node_t* header)
{
    if (node == header)
        return node;
    if (node == header->right)
        return header;
    if (node->right)
        return __rb_left_most(node->right);
    __rb_node_t* par;
    for (;;)
    {
        par = __parent(node);
        if (par->left == node)
            return par;
        node = par;
    }
}

__rb_node_t*
__rb_prev(__rb_node_t* node, __rb_node_t* header)
{
    if (node == header)
        return node->right;
    if (node == header->left)
        return node;
    if (node->left)
        return __rb_right_most(node->left);
    __rb_node_t* par;
    for (;;)
    {
        par = __parent(node);
        if (par->right == node)
            return par;
        node = par;
    }
}

static void
__rb_del0(__rb_node_t* root, void (*__rb_free)(void*, __rb_node_t*), void* args)
{
    if (!root)
        return;
    if (root->left)
        __rb_del0(root->left, __rb_free, args);
    if (root->right)
        __rb_del0(root->right, __rb_free, args);
    __rb_free(args, root);
}

void
__rb_del(__rb_node_t* header,
         void (*__rb_free)(void*, __rb_node_t*),
         void* args)
{
    __rb_del0(__parent(header), __rb_free, args);
    header->left = header->right = header;
    header->parent_color = 0;
}

static __rb_node_t*
__rb_copy0(__rb_node_t* root,
           __rb_node_t* par,
           __rb_node_t* (*__rb_clone)(void*, __rb_node_t*),
           void* args,
           bool* succ)
{
    *succ = false;
    if (!root)
        return NULL;
    __rb_node_t* node = __rb_clone(args, root);
    if (!node)
        return NULL;
    __set_color(node, __color(root));
    node->left = node->right = NULL;
    __set_parent(node, par);
    if (root->left)
    {
        node->left = __rb_copy0(root->left, node, __rb_clone, args, succ);
        if (!*succ)
            return node;
    }
    if (root->right)
    {
        node->right = __rb_copy0(root->right, node, __rb_clone, args, succ);
        if (!*succ)
            return node;
    }
    *succ = true;
    return node;
}

bool
__rb_copy(__rb_node_t* source_header,
          __rb_node_t* (*__rb_clone)(void*, __rb_node_t*),
          void* args,
          __rb_node_t* header)
{
    __rb_node_t* top = __parent(source_header);
    if (!top)
    {
        header->parent_color = 0;
        header->left = header->right = header;
        return true;
    }
    bool succ = false;
    __set_parent(header, __rb_copy0(top, header, __rb_clone, args, &succ));
    if (succ)
    {
        __rb_node_t* root = __parent(header);
        header->left = __rb_left_most(root);
        header->right = __rb_right_most(root);
    }
    return succ;
}

bool
__rb_empty(__rb_node_t* header)
{
    return __parent(header) == NULL;
}

static int
__rb_black_upward(__rb_node_t* node, __rb_node_t* header)
{
    int n = 0;
    while (node != header)
    {
        if (__color(node) == BLACK)
            ++n;
        node = __parent(node);
    }
    return n;
}

static bool
__rb_verify_node(__rb_node_t* node,
                 __rb_node_t* header,
                 int blacks,
                 int (*__rb_cmp)(__rb_node_t*, __rb_node_t*))
{
    __rb_node_t *l = node->left, *r = node->right;
    if (!l && !r)
    {
        return __rb_black_upward(node, header) == blacks;
    }
    if (__color(node) == RED)
    {
        if (l && __color(l) == RED)
            return false;
        if (r && __color(r) == RED)
            return false;
    }
    if (l && __rb_cmp(l, node) > 0)
        return false;
    if (r && __rb_cmp(r, node) < 0)
        return false;
    return true;
}

bool
__rb_verify(__rb_node_t* header, int (*__rb_cmp)(__rb_node_t*, __rb_node_t*))
{
    if (__parent(header) == NULL)
        return header->left == header && header->right == header
               && !header->parent_color;
    __rb_node_t* iter;
    iter = header->left;
    int blacks = __rb_black_upward(iter, header);
    for (; iter != header; iter = __rb_next(iter, header))
    {
        if (!__rb_verify_node(iter, header, blacks, __rb_cmp))
            return false;
    }
    __rb_node_t* root = __parent(header);
    if (header->left != __rb_left_most(root))
        return false;
    if (header->right != __rb_right_most(root))
        return false;
    return true;
}

static bool
__rb_eq0(__rb_node_t* top1,
         __rb_node_t* top2,
         int (*__rb_cmp)(__rb_node_t*, __rb_node_t*))
{
    if (!top1 && !top2)
        return true;
    if (!top1 || !top2)
        return false;
    if (top1 == top2)
        goto __end;
    if (__color(top1) != __color(top2) || __rb_cmp(top1, top2))
        return false;
__end:
    return __rb_eq0(top1->left, top2->left, __rb_cmp)
           && __rb_eq0(top1->right, top2->right, __rb_cmp);
}

bool
__rb_eq(__rb_node_t* header1,
        __rb_node_t* header2,
        int (*__rb_cmp)(__rb_node_t*, __rb_node_t*))
{
    return __rb_eq0(__parent(header1), __parent(header2), __rb_cmp);
}
