#include <stdio.h>
#include <stdlib.h>

#include "../inc/unity.h"
#include "../inc/test_sample.h"

int main(void)
{
    UNITY_BEGIN();
    run_all_tests();
    return UNITY_END();
}
Beispiel Unittest
#include "unity.h"
#include "mbedtls_wrapper.h"  // enthält init_mbedtls(), ServerConfig, MbedtlsContext
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

void test_init_mbedtls_should_initialize_tls_context_successfully(void)
{
    MbedtlsContext ctx;
    ServerConfig conf = {
        .name = "weptech-iot.de",
        .port = "5690",
        .ca_cert = test_ca_cert,          // gültiges PEM-Zertifikat als char[]
        .ca_cert_len = sizeof(test_ca_cert)
    };

    init_mbedtls(conf, &ctx);

    // Beispielhafte Prüfungen
    TEST_ASSERT_NOT_NULL(ctx.conf.ca_chain);
    TEST_ASSERT_NOT_NULL(ctx.conf.f_rng);
    TEST_ASSERT_NOT_NULL(ctx.ssl.conf);
    TEST_ASSERT_EQUAL(MBEDTLS_SSL_VERIFY_REQUIRED, ctx.conf.authmode);
}

void
setUp(void)
{
}

void
tearDown(void)
{
}
