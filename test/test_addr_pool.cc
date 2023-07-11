#include <gtest/gtest.h>
#include <iostream>
using namespace std;
#include <addr_pool.h>
#include <arpa/inet.h>

static void* addr_pool;

class addr_pool_test : public testing::Test
{
public:
    static void
    SetUpTestCase()
    {
        addr_pool = __new_addr_pool(0x0a080000);
        ASSERT_NE(addr_pool, nullptr);
    }

    static void
    TearDownTestCase()
    {
        __del_addr_pool(addr_pool);
    }
};

TEST_F(addr_pool_test, func1)
{
    char ip[16];
    uint32_t addr_list[0x10000];
    uint32_t addr_count = 0;
    for (int i = 0; i < 0xffff; i++)
    {
        uint32_t addr;
        ASSERT_TRUE(__addr_pool_alloc(addr_pool, &addr));
        // cout << "alloc addr:" << inet_ntop(AF_INET, &addr, ip, sizeof(ip))
        //      << endl;
        addr_list[addr_count++] = addr;
    }
    for (int i = 0; i < 0xffff; i++)
    {
        ASSERT_TRUE(__addr_pool_recycle(addr_pool, addr_list[i]));
        uint32_t addr;
        ASSERT_TRUE(__addr_pool_alloc(addr_pool, &addr));
        ASSERT_EQ(addr, addr_list[i]);
    }
}
