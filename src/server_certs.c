#include <server_certs.h>
#include <stddef.h>
#include <certs.h>

static const char ca_crt[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDpTCCAo2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQGEwJDTjEO\r\n"
    "MAwGA1UECAwFYW5odWkxDjAMBgNVBAoMBXpkeGx6MQwwCgYDVQQLDANkZXYxDTAL\r\n"
    "BgNVBAMMBHphY2sxITAfBgkqhkiG9w0BCQEWEnp4azY5ODA5QGdtYWlsLmNvbTAe\r\n"
    "Fw0yMzA2MjcxMTEwMTJaFw00MzA2MjIxMTEwMTJaMG0xCzAJBgNVBAYTAkNOMQ4w\r\n"
    "DAYDVQQIDAVhbmh1aTEOMAwGA1UECgwFemR4bHoxDDAKBgNVBAsMA2RldjENMAsG\r\n"
    "A1UEAwwEemFjazEhMB8GCSqGSIb3DQEJARYSenhrNjk4MDlAZ21haWwuY29tMIIB\r\n"
    "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxXQOPIeNPhbLN0U0Kk5TjniZ\r\n"
    "JRZTXogPCcdQ9HMqbZamo0Bjfl60sq6+lp8iGLDfAf0k8NpgQzJEc1Mcz0RtVs3L\r\n"
    "hP1F46dU4+/rjHfRQ6xGZc2E+ZSY105tAo4ROd/AogXC85UhxgITGi71zIeIKg1N\r\n"
    "JePAl3wnln0y+x9HJ/cnoTok0rokoTDuym2dDv0sef1V6V1b38Xq4NdMa37OR+CK\r\n"
    "D9wUvdu7nvV0UJqG/0hlD/6PGg+Cn9vBnVA3h08WBeNzQIrJ+GueMXSQJAKXbE3e\r\n"
    "5rIIxddOAOj7JkPK8wTvMZ0W2mWELhkscmqJ7WdQfG7jhieKVVQM/+0+KVNZGwID\r\n"
    "AQABo1AwTjAdBgNVHQ4EFgQUiwft9UVxZN+ERiT98l2vWqjTmr0wHwYDVR0jBBgw\r\n"
    "FoAUiwft9UVxZN+ERiT98l2vWqjTmr0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B\r\n"
    "AQsFAAOCAQEAOGp1JaARLQ68rwylZTKvLsP1ptyYdRg5nMlHJkuqmDjnqmPL6QcG\r\n"
    "ET3coI2bthfM5H/DvgUrIVdNXAzoXLOHBJ7KBe7yAHfNOX0JR+yLY7Fl9VVgKDJr\r\n"
    "R0tM3NQihVhMozQEy+teSCxny6rrJjvoam9QX5Z2oOUZKhdtf4nJpfmrTgZw4m2S\r\n"
    "2QqWpB/iEt4wfBHp/3AvtiC9b8qUNz4DtVWg1dXesmJY+YIA33e2EgmJYxu/ObLJ\r\n"
    "ZPN5MP5B/vyYVKDXpV/DNs9m0Xuz3kVDYo+yxV65yHh+/gMY0JH/wXNT6Rfc6iPK\r\n"
    "d1meoKKexNHQiZopczbHeBSXmmk0wilJGA==\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char server_crt[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDrTCCApWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQGEwJDTjEO\r\n"
    "MAwGA1UECAwFYW5odWkxDjAMBgNVBAoMBXpkeGx6MQwwCgYDVQQLDANkZXYxDTAL\r\n"
    "BgNVBAMMBHphY2sxITAfBgkqhkiG9w0BCQEWEnp4azY5ODA5QGdtYWlsLmNvbTAe\r\n"
    "Fw0yMzA2MjcxMTE3MzJaFw0yNDA2MjYxMTE3MzJaMEoxCzAJBgNVBAYTAkNOMQ4w\r\n"
    "DAYDVQQIDAVhbmh1aTEOMAwGA1UECgwFemR4bHoxDDAKBgNVBAsMA2RldjENMAsG\r\n"
    "A1UEAwwEemFjazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALoZk0au\r\n"
    "HubRK8BiKgMfOo4oojsjKVyRGmpnIDgwBBoEtFGe2PDrLc19XFVS08BNFqv6EEEf\r\n"
    "R3uP/a9na2sBAhZSE0+bvuRxNg0ATcrwVeniSM1/ROrDLVSGZqw8sZx1kVo3+ACw\r\n"
    "vf906EJZWUw5DrzNaCuf1M7Dv2spAzUmH9Q7yuq9yF5PpNzrlWzWLBwbHPpbwC1h\r\n"
    "iIBFgcf1REE7V4qC1k52gw6ya9DqaKYtQq/dlXJ1QnZ/nNa5S3VA/1WfZiPUnYph\r\n"
    "4j13fmXhNZDhIeflUX/PO9hkrFve36EB8u7WrfAa/avFGKicmddF9OdbjBb3thpb\r\n"
    "OxM1iC8Coi6pFVcCAwEAAaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYd\r\n"
    "T3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFPF41Km0dm2L\r\n"
    "+o8XH+zn5OG6Fr22MB8GA1UdIwQYMBaAFIsH7fVFcWTfhEYk/fJdr1qo05q9MA0G\r\n"
    "CSqGSIb3DQEBCwUAA4IBAQBZ4UY4NbUY6r40AYWQLgGMnfgm/y4tjRdKguJ0RAX1\r\n"
    "XRCzpBynmUCVYL0gVDRjBL7AttW1zkaOlcIMWMaH1xq0cewnbWOcXPXbYaVnw2Ht\r\n"
    "OPCtSOLtVP46whF1blYSV7VjUjamdLw95xpR2Gyfayy+JpWMUO3jeB7VyjMtrT/U\r\n"
    "jVAmQ6gkInYPv7wTR7K5h/Q5SoURLEBFrvIl0Pz9KHHqRbL5cR1XWb/KMJmQcFXb\r\n"
    "sUvxwqmy7ti6/gvCeycBSxtOtqJOkH8HZE326pBcjW48aZ5ycJ+lDOM/QnH6BZqD\r\n"
    "bJP1XHTueT2EdcbMfZ3VQsEqPqBDc0C1U+UBnTbnznVF\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char server_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "MIIEpAIBAAKCAQEAuhmTRq4e5tErwGIqAx86jiiiOyMpXJEaamcgODAEGgS0UZ7Y\r\n"
    "8OstzX1cVVLTwE0Wq/oQQR9He4/9r2drawECFlITT5u+5HE2DQBNyvBV6eJIzX9E\r\n"
    "6sMtVIZmrDyxnHWRWjf4ALC9/3ToQllZTDkOvM1oK5/UzsO/aykDNSYf1DvK6r3I\r\n"
    "Xk+k3OuVbNYsHBsc+lvALWGIgEWBx/VEQTtXioLWTnaDDrJr0Opopi1Cr92VcnVC\r\n"
    "dn+c1rlLdUD/VZ9mI9SdimHiPXd+ZeE1kOEh5+VRf8872GSsW97foQHy7tat8Br9\r\n"
    "q8UYqJyZ10X051uMFve2Gls7EzWILwKiLqkVVwIDAQABAoIBAQC5HJl/c9FvHN8d\r\n"
    "NUe+5UBUiZydoGMTHY6eCkhlO3XI/6bxjUUTl4tu3GSMxp+0p7mGhW3HqTpscRUR\r\n"
    "dZjGzjDqTOfChxRBnU77bbLzy05aH+j058SAlHYxnqLgblrpW5SinguFfEjxorMo\r\n"
    "1EFb7WF4cgVNZ2XB6bos+JWlN2/vpXv+ObEprAzcNo1Vw42Rix7xKO5/lciZk7hh\r\n"
    "jB4wm3/GO9ZxWwFzIAx3NlFylhUgrMOsJR2OQINKNX4lduw1Ft+CWZkcaCTWqE46\r\n"
    "Rqq5rg7OMxStAo7icUQ20zKoNuCVL1ZNY0fAs72VtvMt7qmpAt8puFW513Hmmx3M\r\n"
    "wVVx3YYZAoGBANsNp7W0Ct9dWpjtwt9z5FvWIm2EeXUncCsGzeGpbnYXDIu0GPNc\r\n"
    "JH3H227tc6/lyiSiW2U3vEm053K4zXEQgXQbWmzI4FMx/lp+c6TT6GYQN+ntNzbG\r\n"
    "JYV3GQd1mn1Hq/a7GX7I7oz2/6oM/QLESoa92SdsYN0QUghMelvyQfIDAoGBANl9\r\n"
    "DDXorSZytyevTMc8RL+f4xIW3ddKEQCrMyDF258MuWvrVNwY+0SmMzEm9HTjymd3\r\n"
    "hgMiwUrV2heOpWYovGU1Xu9Z2MwMXDLKBdAag77IZ9Ff6hdsHtJqLEB/Z8lMe+C7\r\n"
    "kU6tgsTZoaVHZ7M7IBmc/xCL1Ol/6PHcJn1+GjkdAoGBALOn8WKPNVOYhxNh/S+z\r\n"
    "JxlC+J2Fxu+U1uQTAowPn+7uXHW/0a7WZX9biNbjnLwo5K9DEV5kZeK1ohVvB9+x\r\n"
    "P9rwDCuoXIMfP5MMnuAShEohBxquWVhtDpz13utFQt15CMqlDPX06eFnOqxHVsMM\r\n"
    "Jmt4DT/OHWtxVTZFMx1yBS/tAoGAVpMYkT0V8AAqOHnnrkendkBHO6Qumsy5B/Me\r\n"
    "XyVjz2RZS0Rae2LWYvVl22MOXJlwsM87YXQsTYXjUw1NeeUtWXxtVgoF6vPgn7cb\r\n"
    "qUNkvkU4TnhHzxsTCd+JzgLpZZA0n7kKlq8rJwEa/5f1B7u5g3ijcAq5rllkeSKR\r\n"
    "j9LqzWECgYBkwdM8yGCjTTSD0+TEXMIMIXSz3DYzr+d9zfWmXECMYxgiIXPbeuuF\r\n"
    "nJ9F7s0GuHN8Fq057co9x74BWVngwXLGoPJJfBcJgLIlreDZwKLcHbMJBBCdyexn\r\n"
    "a4Jg0VocuV3aKwPziRqhKTPqUKRKhww3LQb3QVByaXOO3cmMNPyPNQ==\r\n"
    "-----END RSA PRIVATE KEY-----\r\n";

const size_t ca_crt_len = sizeof(ca_crt);
const size_t server_crt_len = sizeof(server_crt);
const size_t server_key_len = sizeof(server_key);

const unsigned char *
__get_cert_or_key(__server_cert_opt_t opt, int *len)
{
    switch (opt)
    {
    case CA_CRT:
        *len = ca_crt_len;
        return ca_crt;

    case SERVER_CRT:
        *len = server_crt_len;
        return server_crt;

    case SERVER_KEY:
        *len = server_key_len;
        return server_key;

    default:
        *len = 0;
        return NULL;
    }
}

// const unsigned char*
// __get_cert_or_key(__server_cert_opt_t opt, int* len)
// {
//     switch (opt)
//     {
//     case CA_CRT:
//         *len = mbedtls_test_cas_pem_len;
//         return mbedtls_test_cas_pem;

//     case SERVER_CRT:
//         *len = mbedtls_test_srv_crt_len;
//         return mbedtls_test_srv_crt;

//     case SERVER_KEY:
//         *len = mbedtls_test_srv_key_len;
//         return mbedtls_test_srv_key;

//     default:
//         *len = 0;
//         return NULL;
//     }
// }
