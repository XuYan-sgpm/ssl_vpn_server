#include <gtest/gtest.h>
#include <addr_map.h>
#include <iostream>
#include <util.h>
#include <random>
#include <arpa/inet.h>
using namespace std;

static int data[1024];
static void* m = nullptr;
static char ip[16];
int port;

class addr_map_test : public testing::Test
{
public:
    static void
    SetUpTestCase()
    {
        for (int i = 0; i < 1024; i++)
        {
            data[i] = rand();
        }
        m = _new_addr_map();
        CHECK(m);
        port = 11224;
    }

    static void
    TearDownTestCase()
    {
        _del_addr_map(m);
    }
};

TEST_F(addr_map_test, func1)
{
    int count = 0;
    for (int i = 0; i < 256; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            sprintf(ip, "192.168.%d.%d", i, j);
            uint32_t addr;
            // __set_sock_addr(&addr, ip, port);
            addr = inet_addr(ip);
            ASSERT_TRUE(_addr_map_add(m, addr, &data[(count++) & 1023]));
        }
    }
    cout << "count:" << count << endl;
}

TEST_F(addr_map_test, func2)
{
    int count = 0;
    for (int i = 0; i < 256; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            sprintf(ip, "192.168.%d.%d", i, j);
            uint32_t addr;
            // __set_sock_addr(&addr, ip, port);
            addr = inet_addr(ip);
            int* value = (int*)_addr_map_get(m, addr);
            ASSERT_NE(value, nullptr);
            int* cmp = &data[(count++) & 1023];
            ASSERT_EQ(value, cmp);
        }
    }
}

TEST_F(addr_map_test, func3)
{
    int count = 0;
    int size = 65536;
    ASSERT_EQ(_addr_map_size(m), size);
    for (int i = 0; i < 256; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            sprintf(ip, "192.168.%d.%d", i, j);
            uint32_t addr;
            // __set_sock_addr(&addr, ip, port);
            addr = inet_addr(ip);
            int* value = (int*)_addr_map_remove(m, addr);
            ASSERT_NE(value, nullptr);
            int* cmp = &data[(count++) & 1023];
            ASSERT_EQ(value, cmp);
            ASSERT_EQ(_addr_map_get(m, addr), nullptr);
            ASSERT_EQ(_addr_map_size(m), --size);
        }
    }
    ASSERT_EQ(_addr_map_size(m), 0);
}
