
#include "certs.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include <util.h>
#include <ssl_serv_channel.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <server_certs.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#  include "mbedtls/ssl_cache.h"
#endif

#define DEBUG_LEVEL 0

static void
my_debug(void* ctx, int level, const char* file, int line, const char* str)
{

    __safe_printf("%s:%04d: %s", file, line, str);
}

typedef struct {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif
    mbedtls_net_context proxy;
} __ssl_serv_channel_t;

static void __attribute__((constructor)) __init_log_level()
{
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif
}

static bool
__mbedtls_retry(int ret)
{
    return (ret == MBEDTLS_ERR_SSL_WANT_READ
            || ret == MBEDTLS_ERR_SSL_WANT_WRITE
            || ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS);
}

static bool
__set_serv_channel_bio(void* c, int fd)
{
    __ssl_serv_channel_t* channel = c;
    void** bio = &channel->ssl.private_p_bio;

    if (channel->proxy.fd != fd)
        channel->proxy.fd = fd;
    *bio = (void*)&channel->proxy;

    return true;
}

void*
__new_ssl_serv_channel(int fd)
{
    if (fd <= 0)
        return NULL;
    int _size = sizeof(__ssl_serv_channel_t);
    void* _ptr = malloc(_size);
    if (!_ptr)
        return NULL;
    int ret;
    memset(_ptr, 0, _size);
    __ssl_serv_channel_t* channel = _ptr;

    mbedtls_ssl_init(&channel->ssl);
    channel->ssl.private_f_send = mbedtls_net_send;
    channel->ssl.private_f_recv = mbedtls_net_recv;
    mbedtls_ssl_config_init(&channel->conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&channel->cache);
#endif
    mbedtls_x509_crt_init(&channel->srvcert);
    mbedtls_pk_init(&channel->pkey);
    mbedtls_entropy_init(&channel->entropy);
    mbedtls_ctr_drbg_init(&channel->ctr_drbg);
    const char* pers = "ssl_server";

    __set_serv_channel_bio(channel, fd);

    __safe_printf("  . Seeding the random number generator...");

    if ((ret = mbedtls_ctr_drbg_seed(&channel->ctr_drbg,
                                     mbedtls_entropy_func,
                                     &channel->entropy,
                                     (const unsigned char*)pers,
                                     strlen(pers)))
        != 0)
    {
        __safe_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    __safe_printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    __safe_printf("\n  . Loading the server cert. and key...");

    int ca_crt_len, server_crt_len, server_key_len;
    const unsigned char *ca_crt, *server_crt, *server_key;

    ca_crt = __get_cert_or_key(CA_CRT, &ca_crt_len);
    server_crt = __get_cert_or_key(SERVER_CRT, &server_crt_len);
    server_key = __get_cert_or_key(SERVER_KEY, &server_key_len);

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse(&channel->srvcert, server_crt, server_crt_len);
    if (ret != 0)
    {
        __safe_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n",
                      ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&channel->srvcert, ca_crt, ca_crt_len);
    if (ret != 0)
    {
        __safe_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n",
                      ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_key(&channel->pkey,
                               server_key,
                               server_key_len,
                               NULL,
                               0,
                               mbedtls_ctr_drbg_random,
                               &channel->ctr_drbg);
    if (ret != 0)
    {
        __safe_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n",
                      ret);
        goto exit;
    }

    __safe_printf(" ok\n");

    __safe_printf("  . Setting up the SSL data....");

    if ((ret = mbedtls_ssl_config_defaults(&channel->conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT))
        != 0)
    {
        __safe_printf(
            " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
            ret);
        goto exit;
    }
    
    // mbedtls_ssl_conf_authmode(&channel->conf, 2);

    mbedtls_ssl_conf_rng(&channel->conf,
                         mbedtls_ctr_drbg_random,
                         &channel->ctr_drbg);
    mbedtls_ssl_conf_dbg(&channel->conf, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&channel->conf,
                                   &channel->cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&channel->conf, channel->srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&channel->conf,
                                         &channel->srvcert,
                                         &channel->pkey))
        != 0)
    {
        __safe_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n",
                      ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&channel->ssl, &channel->conf)) != 0)
    {
        __safe_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    __safe_printf(" ok\n");
    return channel;
exit:

    __del_ssl_serv_channel(channel);
    return NULL;
}

void
__del_ssl_serv_channel(void* c)
{
    __ssl_serv_channel_t* channel = c;
    mbedtls_x509_crt_free(&channel->srvcert);
    mbedtls_pk_free(&channel->pkey);
    mbedtls_ssl_free(&channel->ssl);
    mbedtls_ssl_config_free(&channel->conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&channel->cache);
#endif
    mbedtls_ctr_drbg_free(&channel->ctr_drbg);
    mbedtls_entropy_free(&channel->entropy);

    free(channel);
}

int
__ssl_serv_channel_read(void* c, void* buf, int len)
{
    __ssl_serv_channel_t* channel = c;
    return mbedtls_ssl_read(&channel->ssl, buf, len);
}

int
__ssl_serv_channel_write(void* c, const void* buf, int len)
{
    __ssl_serv_channel_t* channel = c;
    return mbedtls_ssl_write(&channel->ssl, buf, len);
}

static void
__show_ssl_error(int err)
{
    char buf[100];
    mbedtls_strerror(err, buf, 100);
    __safe_printf("Last error was: %d - %s\n\n", err, buf);
}

int
__ssl_serv_channel_handshake(void* c)
{
    __ssl_serv_channel_t* channel = c;

    int ret;

    __safe_printf("  . Performing the SSL/TLS handshake...");

    ret = mbedtls_ssl_handshake(&channel->ssl);
    if (ret == 0)
    {
        __safe_printf(" ok\n");
        return 0;
    }
    if (!__mbedtls_retry(ret))
    {
        __safe_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n",
                      ret);
        goto error;
    }
    __safe_printf("handshake incomplete yet\n");

    return ret;
error:
    __show_ssl_error(ret);
    __set_serv_channel_bio(c, -1);
    return ret;
}

int
__ssl_serv_channel_close(void* c)
{
    __safe_printf("  . Closing the connection...");
    __ssl_serv_channel_t* channel = c;
    int ret;

    ret = mbedtls_ssl_close_notify(&channel->ssl);
    if (ret == 0)
    {
        __safe_printf(" ok\n");
        return 0;
    }
    if (ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {

        __safe_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n",
                      ret);
        goto end;
    }

    __safe_printf(" close not complete yet\n");
    return ret;
end:
    __set_serv_channel_bio(c, -1);
    return ret;
}
