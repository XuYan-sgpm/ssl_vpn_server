#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    CA_CRT,
    SERVER_CRT,
    SERVER_KEY
} __server_cert_opt_t;

const unsigned char*
__get_cert_or_key(__server_cert_opt_t opt, int* len);

#ifdef __cplusplus
}
#endif
