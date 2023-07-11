#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union
{
    struct {
        uint32_t pac_flag; // packet flag, 0xaabbccdd
        uint16_t pac_len;  // packet length
        uint16_t pac_type; // packet type
    };
    uint8_t data[8];
} __packet_header_t;

typedef enum
{
    PACKET_IP_DATA = 0x0, // ip packet, send to tun0
    PACKET_IP_COMMAND,    // negotiate ip command, send by server
    PACKET_IP_ACK,        // ip command ack
    PACKET_HEARTBEAT,     // heartbeat packet, send by server to test client
    PACKET_HEARTBEAT_ACK, // heartbeat response, client send to server when recv
                          // server heartbeat
    MAX_PACKET_TYPE
} __packet_type_t;

#ifdef __cplusplus
}
#endif
