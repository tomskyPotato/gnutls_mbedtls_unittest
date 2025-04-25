#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : .\test_suite_pkcs1_v15.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/main_test.function
 *      Platform code file  : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/host_test.function
 *      Helper file         : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/helpers.function
 *      Test suite file     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.function
 *      Test suite data     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.data
 *
 */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L // for fileno() from <stdio.h>
#endif
#endif

#include "mbedtls/build_info.h"

/* Test code may use deprecated identifiers only if the preprocessor symbol
 * MBEDTLS_TEST_DEPRECATED is defined. When building tests, set
 * MBEDTLS_TEST_DEPRECATED explicitly if MBEDTLS_DEPRECATED_WARNING is
 * enabled but the corresponding warnings are not treated as errors.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_TEST_DEPRECATED
#endif

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <test/arguments.h>
#include <test/helpers.h>
#include <test/macros.h>
#include <test/random.h>
#include <test/bignum_helpers.h>
#include <test/psa_crypto_helpers.h>
#include <test/threading_helpers.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(MBEDTLS_ERROR_C)
#include "mbedtls/error.h"
#endif
#include "mbedtls/platform.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

/*----------------------------------------------------------------------------*/
/* Global variables */

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
    (!defined(MBEDTLS_NO_PLATFORM_ENTROPY) ||       \
    defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||        \
    defined(ENTROPY_NV_SEED))
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output(FILE *out_stream, const char *path)
{
    int out_fd, dup_fd;
    FILE *path_stream;

    out_fd = fileno(out_stream);
    dup_fd = dup(out_fd);

    if (dup_fd == -1) {
        return -1;
    }

    path_stream = fopen(path, "w");
    if (path_stream == NULL) {
        close(dup_fd);
        return -1;
    }

    fflush(out_stream);
    if (dup2(fileno(path_stream), out_fd) == -1) {
        close(dup_fd);
        fclose(path_stream);
        return -1;
    }

    fclose(path_stream);
    return dup_fd;
}

static int restore_output(FILE *out_stream, int dup_fd)
{
    int out_fd = fileno(out_stream);

    fflush(out_stream);
    if (dup2(dup_fd, out_fd) == -1) {
        close(out_fd);
        close(dup_fd);
        return -1;
    }

    close(dup_fd);
    return 0;
}
#endif /* __unix__ || __APPLE__ __MACH__ */


#line 43 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#line 2 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.function"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#line 12 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.function"
static void test_pkcs1_rsaes_v15_encrypt(int mod, char *input_N,
                             char *input_E, int hash,
                             data_t *message_str, data_t *rnd_buf,
                             data_t *result_str, int result)
{
    unsigned char output[128];
    mbedtls_rsa_context ctx;
    mbedtls_test_rnd_buf_info info;
    mbedtls_mpi N, E;

    info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    info.fallback_p_rng = NULL;
    info.buf = rnd_buf->x;
    info.length = rnd_buf->len;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx);

    TEST_EQUAL(mbedtls_rsa_get_padding_mode(&ctx), MBEDTLS_RSA_PKCS_V15);
    TEST_EQUAL(mbedtls_rsa_get_md_alg(&ctx), MBEDTLS_MD_NONE);

    TEST_ASSERT(mbedtls_rsa_set_padding(&ctx,
                                        MBEDTLS_RSA_PKCS_V15, hash) == 0);
    memset(output, 0x00, sizeof(output));

    TEST_EQUAL(mbedtls_rsa_get_padding_mode(&ctx), MBEDTLS_RSA_PKCS_V15);
    TEST_EQUAL(mbedtls_rsa_get_md_alg(&ctx), hash);

    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, NULL, NULL, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_check_pubkey(&ctx) == 0);

    if (message_str->len == 0) {
        message_str->x = NULL;
    }
    TEST_ASSERT(mbedtls_rsa_pkcs1_encrypt(&ctx,
                                          &mbedtls_test_rnd_buffer_rand,
                                          &info, message_str->len,
                                          message_str->x,
                                          output) == result);

    if (result == 0) {
        TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                        ctx.len, result_str->len) == 0);
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

static void test_pkcs1_rsaes_v15_encrypt_wrapper( void ** params )
{
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};
    data_t data8 = {(uint8_t *) params[8], ((mbedtls_test_argument_t *) params[9])->len};

    test_pkcs1_rsaes_v15_encrypt( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint, &data4, &data6, &data8, ((mbedtls_test_argument_t *) params[10])->sint );
}
#line 67 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.function"
static void test_pkcs1_rsaes_v15_decrypt(int mod, char *input_P, char *input_Q,
                             char *input_N, char *input_E, int hash,
                             data_t *result_str, char *seed,
                             data_t *message_str, int result)
{
    unsigned char output[128];
    mbedtls_rsa_context ctx;
    size_t output_len;
    mbedtls_test_rnd_pseudo_info rnd_info;
    mbedtls_mpi N, P, Q, E;
    ((void) seed);

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx);
    TEST_ASSERT(mbedtls_rsa_set_padding(&ctx,
                                        MBEDTLS_RSA_PKCS_V15, hash) == 0);

    TEST_EQUAL(mbedtls_rsa_get_padding_mode(&ctx), MBEDTLS_RSA_PKCS_V15);
    TEST_EQUAL(mbedtls_rsa_get_md_alg(&ctx), hash);

    memset(output, 0x00, sizeof(output));
    memset(&rnd_info, 0, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);

    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, &P, &Q, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_complete(&ctx) == 0);
    TEST_ASSERT(mbedtls_rsa_check_privkey(&ctx) == 0);

    if (result_str->len == 0) {
        TEST_ASSERT(mbedtls_rsa_pkcs1_decrypt(&ctx,
                                              &mbedtls_test_rnd_pseudo_rand,
                                              &rnd_info,
                                              &output_len, message_str->x,
                                              NULL, 0) == result);
    } else {
        TEST_ASSERT(mbedtls_rsa_pkcs1_decrypt(&ctx,
                                              &mbedtls_test_rnd_pseudo_rand,
                                              &rnd_info,
                                              &output_len, message_str->x,
                                              output, 1000) == result);
        if (result == 0) {
            TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                            output_len,
                                            result_str->len) == 0);
        }
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

static void test_pkcs1_rsaes_v15_decrypt_wrapper( void ** params )
{
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};
    data_t data9 = {(uint8_t *) params[9], ((mbedtls_test_argument_t *) params[10])->len};

    test_pkcs1_rsaes_v15_decrypt( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], ((mbedtls_test_argument_t *) params[5])->sint, &data6, (char *) params[8], &data9, ((mbedtls_test_argument_t *) params[11])->sint );
}
#line 128 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.function"
static void test_pkcs1_v15_decode(data_t *input,
                      int expected_plaintext_length_arg,
                      int output_size_arg,
                      int expected_result)
{
    size_t expected_plaintext_length = expected_plaintext_length_arg;
    size_t output_size = output_size_arg;
    mbedtls_test_rnd_pseudo_info rnd_info;
    mbedtls_mpi Nmpi, Empi, Pmpi, Qmpi;
    mbedtls_rsa_context ctx;
    static unsigned char N[128] = {
        0xc4, 0x79, 0x4c, 0x6d, 0xb2, 0xe9, 0xdf, 0xc5,
        0xe5, 0xd7, 0x55, 0x4b, 0xfb, 0x6c, 0x2e, 0xec,
        0x84, 0xd0, 0x88, 0x12, 0xaf, 0xbf, 0xb4, 0xf5,
        0x47, 0x3c, 0x7e, 0x92, 0x4c, 0x58, 0xc8, 0x73,
        0xfe, 0x8f, 0x2b, 0x8f, 0x8e, 0xc8, 0x5c, 0xf5,
        0x05, 0xeb, 0xfb, 0x0d, 0x7b, 0x2a, 0x93, 0xde,
        0x15, 0x0d, 0xc8, 0x13, 0xcf, 0xd2, 0x6f, 0x0d,
        0x9d, 0xad, 0x30, 0xe5, 0x70, 0x20, 0x92, 0x9e,
        0xb3, 0x6b, 0xba, 0x5c, 0x50, 0x0f, 0xc3, 0xb2,
        0x7e, 0x64, 0x07, 0x94, 0x7e, 0xc9, 0x4e, 0xc1,
        0x65, 0x04, 0xaf, 0xb3, 0x9f, 0xde, 0xa8, 0x46,
        0xfa, 0x6c, 0xf3, 0x03, 0xaf, 0x1c, 0x1b, 0xec,
        0x75, 0x44, 0x66, 0x77, 0xc9, 0xde, 0x51, 0x33,
        0x64, 0x27, 0xb0, 0xd4, 0x8d, 0x31, 0x6a, 0x11,
        0x27, 0x3c, 0x99, 0xd4, 0x22, 0xc0, 0x9d, 0x12,
        0x01, 0xc7, 0x4a, 0x73, 0xac, 0xbf, 0xc2, 0xbb
    };
    static unsigned char E[1] = { 0x03 };
    static unsigned char P[64] = {
        0xe5, 0x53, 0x1f, 0x88, 0x51, 0xee, 0x59, 0xf8,
        0xc1, 0xe4, 0xcc, 0x5b, 0xb3, 0x75, 0x8d, 0xc8,
        0xe8, 0x95, 0x2f, 0xd0, 0xef, 0x37, 0xb4, 0xcd,
        0xd3, 0x9e, 0x48, 0x8b, 0x81, 0x58, 0x60, 0xb9,
        0x27, 0x1d, 0xb6, 0x28, 0x92, 0x64, 0xa3, 0xa5,
        0x64, 0xbd, 0xcc, 0x53, 0x68, 0xdd, 0x3e, 0x55,
        0xea, 0x9d, 0x5e, 0xcd, 0x1f, 0x96, 0x87, 0xf1,
        0x29, 0x75, 0x92, 0x70, 0x8f, 0x28, 0xfb, 0x2b
    };
    static unsigned char Q[64] = {
        0xdb, 0x53, 0xef, 0x74, 0x61, 0xb4, 0x20, 0x3b,
        0x3b, 0x87, 0x76, 0x75, 0x81, 0x56, 0x11, 0x03,
        0x59, 0x31, 0xe3, 0x38, 0x4b, 0x8c, 0x7a, 0x9c,
        0x05, 0xd6, 0x7f, 0x1e, 0x5e, 0x60, 0xf0, 0x4e,
        0x0b, 0xdc, 0x34, 0x54, 0x1c, 0x2e, 0x90, 0x83,
        0x14, 0xef, 0xc0, 0x96, 0x5c, 0x30, 0x10, 0xcc,
        0xc1, 0xba, 0xa0, 0x54, 0x3f, 0x96, 0x24, 0xca,
        0xa3, 0xfb, 0x55, 0xbc, 0x71, 0x29, 0x4e, 0xb1
    };
    unsigned char original[128];
    unsigned char intermediate[128];
    static unsigned char default_content[128] = {
        /* A randomly generated pattern. */
        0x4c, 0x27, 0x54, 0xa0, 0xce, 0x0d, 0x09, 0x4a,
        0x1c, 0x38, 0x8e, 0x2d, 0xa3, 0xc4, 0xe0, 0x19,
        0x4c, 0x99, 0xb2, 0xbf, 0xe6, 0x65, 0x7e, 0x58,
        0xd7, 0xb6, 0x8a, 0x05, 0x2f, 0xa5, 0xec, 0xa4,
        0x35, 0xad, 0x10, 0x36, 0xff, 0x0d, 0x08, 0x50,
        0x74, 0x47, 0xc9, 0x9c, 0x4a, 0xe7, 0xfd, 0xfa,
        0x83, 0x5f, 0x14, 0x5a, 0x1e, 0xe7, 0x35, 0x08,
        0xad, 0xf7, 0x0d, 0x86, 0xdf, 0xb8, 0xd4, 0xcf,
        0x32, 0xb9, 0x5c, 0xbe, 0xa3, 0xd2, 0x89, 0x70,
        0x7b, 0xc6, 0x48, 0x7e, 0x58, 0x4d, 0xf3, 0xef,
        0x34, 0xb7, 0x57, 0x54, 0x79, 0xc5, 0x8e, 0x0a,
        0xa3, 0xbf, 0x6d, 0x42, 0x83, 0x25, 0x13, 0xa2,
        0x95, 0xc0, 0x0d, 0x32, 0xec, 0x77, 0x91, 0x2b,
        0x68, 0xb6, 0x8c, 0x79, 0x15, 0xfb, 0x94, 0xde,
        0xb9, 0x2b, 0x94, 0xb3, 0x28, 0x23, 0x86, 0x3d,
        0x37, 0x00, 0xe6, 0xf1, 0x1f, 0x4e, 0xd4, 0x42
    };
    unsigned char final[128];
    size_t output_length = 0x7EA0;

    memset(&rnd_info, 0, sizeof(mbedtls_test_rnd_pseudo_info));
    mbedtls_mpi_init(&Nmpi); mbedtls_mpi_init(&Empi);
    mbedtls_mpi_init(&Pmpi); mbedtls_mpi_init(&Qmpi);
    mbedtls_rsa_init(&ctx);

    TEST_ASSERT(mbedtls_mpi_read_binary(&Nmpi, N, sizeof(N)) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&Empi, E, sizeof(E)) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&Pmpi, P, sizeof(P)) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&Qmpi, Q, sizeof(Q)) == 0);

    TEST_ASSERT(mbedtls_rsa_import(&ctx, &Nmpi, &Pmpi, &Qmpi,
                                   NULL, &Empi) == 0);
    TEST_ASSERT(mbedtls_rsa_complete(&ctx) == 0);

    TEST_ASSERT(input->len <= sizeof(N));
    memcpy(original, input->x, input->len);
    memset(original + input->len, 'd', sizeof(original) - input->len);
    TEST_ASSERT(mbedtls_rsa_public(&ctx, original, intermediate) == 0);

    memcpy(final, default_content, sizeof(final));
    TEST_ASSERT(mbedtls_rsa_pkcs1_decrypt(&ctx,
                                          &mbedtls_test_rnd_pseudo_rand,
                                          &rnd_info, &output_length,
                                          intermediate, final,
                                          output_size) == expected_result);
    if (expected_result == 0) {
        TEST_ASSERT(output_length == expected_plaintext_length);
        TEST_ASSERT(memcmp(original + sizeof(N) - output_length,
                           final,
                           output_length) == 0);
    } else if (expected_result == MBEDTLS_ERR_RSA_INVALID_PADDING ||
               expected_result == MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE) {
        size_t max_payload_length =
            output_size > sizeof(N) - 11 ? sizeof(N) - 11 : output_size;
        size_t i;
        size_t count = 0;

#if !defined(MBEDTLS_RSA_ALT)
        /* Check that the output in invalid cases is what the default
         * implementation currently does. Alternative implementations
         * may produce different output, so we only perform these precise
         * checks when using the default implementation. */
        TEST_ASSERT(output_length == max_payload_length);
        for (i = 0; i < max_payload_length; i++) {
            TEST_ASSERT(final[i] == 0);
        }
#endif
        /* Even in alternative implementations, the outputs must have
         * changed, otherwise it indicates at least a timing vulnerability
         * because no write to the outputs is performed in the bad case. */
        TEST_ASSERT(output_length != 0x7EA0);
        for (i = 0; i < max_payload_length; i++) {
            count += (final[i] == default_content[i]);
        }
        /* If more than 16 bytes are unchanged in final, that's evidence
         * that final wasn't overwritten. */
        TEST_ASSERT(count < 16);
    }

exit:
    mbedtls_mpi_free(&Nmpi); mbedtls_mpi_free(&Empi);
    mbedtls_mpi_free(&Pmpi); mbedtls_mpi_free(&Qmpi);
    mbedtls_rsa_free(&ctx);
}

static void test_pkcs1_v15_decode_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_pkcs1_v15_decode( &data0, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#line 268 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.function"
static void test_pkcs1_rsassa_v15_sign(int mod, char *input_P,
                           char *input_Q, char *input_N,
                           char *input_E, int digest, int hash,
                           data_t *message_str, data_t *rnd_buf,
                           data_t *result_str, int result)
{
    unsigned char output[128];
    mbedtls_rsa_context ctx;
    mbedtls_mpi N, P, Q, E;
    mbedtls_test_rnd_buf_info info;

    info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    info.fallback_p_rng = NULL;
    info.buf = rnd_buf->x;
    info.length = rnd_buf->len;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx);
    TEST_ASSERT(mbedtls_rsa_set_padding(&ctx,
                                        MBEDTLS_RSA_PKCS_V15, hash) == 0);

    memset(output, 0x00, sizeof(output));

    TEST_EQUAL(mbedtls_rsa_get_padding_mode(&ctx), MBEDTLS_RSA_PKCS_V15);
    TEST_EQUAL(mbedtls_rsa_get_md_alg(&ctx), hash);

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);

    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, &P, &Q, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_complete(&ctx) == 0);
    TEST_ASSERT(mbedtls_rsa_check_privkey(&ctx) == 0);

    TEST_ASSERT(mbedtls_rsa_pkcs1_sign(
                    &ctx, &mbedtls_test_rnd_buffer_rand, &info,
                    digest, message_str->len, message_str->x,
                    output) == result);
    if (result == 0) {

        TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                        ctx.len, result_str->len) == 0);
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

static void test_pkcs1_rsassa_v15_sign_wrapper( void ** params )
{
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};
    data_t data9 = {(uint8_t *) params[9], ((mbedtls_test_argument_t *) params[10])->len};
    data_t data11 = {(uint8_t *) params[11], ((mbedtls_test_argument_t *) params[12])->len};

    test_pkcs1_rsassa_v15_sign( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, &data7, &data9, &data11, ((mbedtls_test_argument_t *) params[13])->sint );
}
#line 323 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_pkcs1_v15.function"
static void test_pkcs1_rsassa_v15_verify(int mod, char *input_N, char *input_E,
                             int digest, int hash, data_t *message_str,
                             char *salt, data_t *result_str, int result)
{
    mbedtls_rsa_context ctx;
    mbedtls_mpi N, E;
    ((void) salt);

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx);
    TEST_ASSERT(mbedtls_rsa_set_padding(&ctx,
                                        MBEDTLS_RSA_PKCS_V15, hash) == 0);

    TEST_EQUAL(mbedtls_rsa_get_padding_mode(&ctx), MBEDTLS_RSA_PKCS_V15);
    TEST_EQUAL(mbedtls_rsa_get_md_alg(&ctx), hash);

    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, NULL, NULL, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_check_pubkey(&ctx) == 0);

    TEST_ASSERT(mbedtls_rsa_pkcs1_verify(&ctx, digest, message_str->len, message_str->x,
                                         result_str->x) == result);

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

static void test_pkcs1_rsassa_v15_verify_wrapper( void ** params )
{
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};
    data_t data8 = {(uint8_t *) params[8], ((mbedtls_test_argument_t *) params[9])->len};

    test_pkcs1_rsassa_v15_verify( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, &data5, (char *) params[7], &data8, ((mbedtls_test_argument_t *) params[10])->sint );
}
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */


#line 54 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
static int get_expression(int32_t exp_id, intmax_t *out_value)
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch (exp_id) {
    
#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)

        case 0:
            {
                *out_value = MBEDTLS_MD_NONE;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ERR_RSA_INVALID_PADDING;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
            }
            break;
#endif

#line 82 "suites/main_test.function"
        default:
        {
            ret = KEY_VALUE_MAPPING_NOT_FOUND;
        }
        break;
    }
    return ret;
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param dep_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
static int dep_check(int dep_id)
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch (dep_id) {
    
#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)

        case 0:
            {
#if defined(MBEDTLS_MD_CAN_SHA1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 112 "suites/main_test.function"
        default:
            break;
    }
    return ret;
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 * A test function wrapper decodes the parameters and passes them to the
 * underlying test function. Both the wrapper and the underlying function
 * return void. Test wrappers assume that they are passed a suitable
 * parameter array and do not perform any error detection.
 *
 * \param param_array   The array of parameters. Each element is a `void *`
 *                      which the wrapper casts to the correct type and
 *                      dereferences. Each wrapper function hard-codes the
 *                      number and types of the parameters.
 */
typedef void (*TestWrapper_t)(void **param_array);


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
    /* Function Id: 0 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)
    test_pkcs1_rsaes_v15_encrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)
    test_pkcs1_rsaes_v15_decrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)
    test_pkcs1_v15_decode_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)
    test_pkcs1_rsassa_v15_sign_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C)
    test_pkcs1_rsassa_v15_verify_wrapper,
#else
    NULL,
#endif

#line 145 "suites/main_test.function"
};

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param func_idx    Test function index.
 * \param params      The array of parameters to pass to the test function.
 *                    It will be decoded by the #TestWrapper_t wrapper function.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
static int dispatch_test(size_t func_idx, void **params)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs) / sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp) {
            #if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
            mbedtls_test_enable_insecure_external_rng();
            #endif

            fp(params);

            #if defined(MBEDTLS_TEST_MUTEX_USAGE)
            mbedtls_test_mutex_usage_check();
            #endif /* MBEDTLS_TEST_MUTEX_USAGE */
        } else {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


/**
 * \brief       Checks if test function is supported in this build-time
 *              configuration.
 *
 * \param func_idx    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
static int check_test(size_t func_idx)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs)/sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp == NULL) {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
static int verify_string(char **str)
{
    if ((*str)[0] != '"' ||
        (*str)[strlen(*str) - 1] != '"') {
        mbedtls_fprintf(stderr,
                        "Expected string (with \"\") for parameter and got: %s\n", *str);
        return -1;
    }

    (*str)++;
    (*str)[strlen(*str) - 1] = '\0';

    return 0;
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param p_value Pointer to output value.
 *
 * \return      0 if success else 1
 */
static int verify_int(char *str, intmax_t *p_value)
{
    char *end = NULL;
    errno = 0;
    /* Limit the range to long: for large integers, the test framework will
     * use expressions anyway. */
    long value = strtol(str, &end, 0);
    if (errno == EINVAL || *end != '\0') {
        mbedtls_fprintf(stderr,
                        "Expected integer for parameter and got: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    if (errno == ERANGE) {
        mbedtls_fprintf(stderr, "Integer out of range: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    *p_value = value;
    return 0;
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Read a line from the passed file pointer.
 *
 * \param f     FILE pointer
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
static int get_line(FILE *f, char *buf, size_t len)
{
    char *ret;
    int i = 0, str_len = 0, has_string = 0;

    /* Read until we get a valid line */
    do {
        ret = fgets(buf, len, f);
        if (ret == NULL) {
            return -1;
        }

        str_len = strlen(buf);

        /* Skip empty line and comment */
        if (str_len == 0 || buf[0] == '#') {
            continue;
        }
        has_string = 0;
        for (i = 0; i < str_len; i++) {
            char c = buf[i];
            if (c != ' ' && c != '\t' && c != '\n' &&
                c != '\v' && c != '\f' && c != '\r') {
                has_string = 1;
                break;
            }
        }
    } while (!has_string);

    /* Strip new line and carriage return */
    ret = buf + strlen(buf);
    if (ret-- > buf && *ret == '\n') {
        *ret = '\0';
    }
    if (ret-- > buf && *ret == '\r') {
        *ret = '\0';
    }

    return 0;
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments(char *buf, size_t len, char **params,
                           size_t params_len)
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while (*p != '\0' && p < (buf + len)) {
        if (*p == '\\') {
            p++;
            p++;
            continue;
        }
        if (*p == ':') {
            if (p + 1 < buf + len) {
                cur = p + 1;
                TEST_HELPER_ASSERT(cnt < params_len);
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace backslash escapes in strings */
    for (i = 0; i < cnt; i++) {
        p = params[i];
        q = params[i];

        while (*p != '\0') {
            if (*p == '\\') {
                ++p;
                switch (*p) {
                    case 'n':
                        *p = '\n';
                        break;
                    default:
                        // Fall through to copying *p
                        break;
                }
            }
            *(q++) = *(p++);
        }
        *q = '\0';
    }

    return cnt;
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params(size_t cnt, char **params,
                          mbedtls_test_argument_t *int_params_store)
{
    char **cur = params;
    char **out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while (cur < params + cnt) {
        char *type = *cur++;
        char *val = *cur++;

        if (strcmp(type, "char*") == 0) {
            if (verify_string(&val) == 0) {
                *out++ = val;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "int") == 0) {
            if (verify_int(val, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "hex") == 0) {
            if (verify_string(&val) == 0) {
                size_t len;

                TEST_HELPER_ASSERT(
                    mbedtls_test_unhexify((unsigned char *) val, strlen(val),
                                          val, &len) == 0);

                int_params_store->len = len;
                *out++ = val;
                *out++ = (char *) (int_params_store++);
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "exp") == 0) {
            int exp_id = strtol(val, NULL, 10);
            if (get_expression(exp_id, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else {
            ret = (DISPATCH_INVALID_TEST_DATA);
            break;
        }
    }
    return ret;
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf(size_t n, const char *ref_buf, int ref_ret)
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if (n >= sizeof(buf)) {
        return -1;
    }
    ret = mbedtls_snprintf(buf, n, "%s", "123");
    if (ret < 0 || (size_t) ret >= n) {
        ret = -1;
    }

    if (strncmp(ref_buf, buf, sizeof(buf)) != 0 ||
        ref_ret != ret ||
        memcmp(buf + n, ref + n, sizeof(buf) - n) != 0) {
        return 1;
    }

    return 0;
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf(void)
{
    return test_snprintf(0, "xxxxxxxxx",  -1) != 0 ||
           test_snprintf(1, "",           -1) != 0 ||
           test_snprintf(2, "1",          -1) != 0 ||
           test_snprintf(3, "12",         -1) != 0 ||
           test_snprintf(4, "123",         3) != 0 ||
           test_snprintf(5, "123",         3) != 0;
}

/** \brief Write the description of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param argv0         The test suite name.
 * \param test_case     The test case description.
 */
static void write_outcome_entry(FILE *outcome_file,
                                const char *argv0,
                                const char *test_case)
{
    /* The non-varying fields are initialized on first use. */
    static const char *platform = NULL;
    static const char *configuration = NULL;
    static const char *test_suite = NULL;

    if (outcome_file == NULL) {
        return;
    }

    if (platform == NULL) {
        platform = getenv("MBEDTLS_TEST_PLATFORM");
        if (platform == NULL) {
            platform = "unknown";
        }
    }
    if (configuration == NULL) {
        configuration = getenv("MBEDTLS_TEST_CONFIGURATION");
        if (configuration == NULL) {
            configuration = "unknown";
        }
    }
    if (test_suite == NULL) {
        test_suite = strrchr(argv0, '/');
        if (test_suite != NULL) {
            test_suite += 1; // skip the '/'
        } else {
            test_suite = argv0;
        }
    }

    /* Write the beginning of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    mbedtls_fprintf(outcome_file, "%s;%s;%s;%s;",
                    platform, configuration, test_suite, test_case);
}

/** \brief Write the result of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param unmet_dep_count            The number of unmet dependencies.
 * \param unmet_dependencies         The array of unmet dependencies.
 * \param missing_unmet_dependencies Non-zero if there was a problem tracking
 *                                   all unmet dependencies, 0 otherwise.
 * \param ret                        The test dispatch status (DISPATCH_xxx).
 */
static void write_outcome_result(FILE *outcome_file,
                                 size_t unmet_dep_count,
                                 int unmet_dependencies[],
                                 int missing_unmet_dependencies,
                                 int ret)
{
    if (outcome_file == NULL) {
        return;
    }

    /* Write the end of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    switch (ret) {
        case DISPATCH_TEST_SUCCESS:
            if (unmet_dep_count > 0) {
                size_t i;
                mbedtls_fprintf(outcome_file, "SKIP");
                for (i = 0; i < unmet_dep_count; i++) {
                    mbedtls_fprintf(outcome_file, "%c%d",
                                    i == 0 ? ';' : ':',
                                    unmet_dependencies[i]);
                }
                if (missing_unmet_dependencies) {
                    mbedtls_fprintf(outcome_file, ":...");
                }
                break;
            }
            switch (mbedtls_test_get_result()) {
                case MBEDTLS_TEST_RESULT_SUCCESS:
                    mbedtls_fprintf(outcome_file, "PASS;");
                    break;
                case MBEDTLS_TEST_RESULT_SKIPPED:
                    mbedtls_fprintf(outcome_file, "SKIP;Runtime skip");
                    break;
                default:
                    mbedtls_fprintf(outcome_file, "FAIL;%s:%d:%s",
                                    mbedtls_get_test_filename(),
                                    mbedtls_test_get_line_no(),
                                    mbedtls_test_get_test());
                    break;
            }
            break;
        case DISPATCH_TEST_FN_NOT_FOUND:
            mbedtls_fprintf(outcome_file, "FAIL;Test function not found");
            break;
        case DISPATCH_INVALID_TEST_DATA:
            mbedtls_fprintf(outcome_file, "FAIL;Invalid test data");
            break;
        case DISPATCH_UNSUPPORTED_SUITE:
            mbedtls_fprintf(outcome_file, "SKIP;Unsupported suite");
            break;
        default:
            mbedtls_fprintf(outcome_file, "FAIL;Unknown cause");
            break;
    }
    mbedtls_fprintf(outcome_file, "\n");
    fflush(outcome_file);
}

#if defined(__unix__) ||                                \
    (defined(__APPLE__) && defined(__MACH__))
#define MBEDTLS_HAVE_CHDIR
#endif

#if defined(MBEDTLS_HAVE_CHDIR)
/** Try chdir to the directory containing argv0.
 *
 * Failures are silent.
 */
static void try_chdir_if_supported(const char *argv0)
{
    /* We might want to allow backslash as well, for Windows. But then we also
     * need to consider chdir() vs _chdir(), and different conventions
     * regarding paths in argv[0] (naively enabling this code with
     * backslash support on Windows leads to chdir into the wrong directory
     * on the CI). */
    const char *slash = strrchr(argv0, '/');
    if (slash == NULL) {
        return;
    }
    size_t path_size = slash - argv0 + 1;
    char *path = mbedtls_calloc(1, path_size);
    if (path == NULL) {
        return;
    }
    memcpy(path, argv0, path_size - 1);
    path[path_size - 1] = 0;
    int ret = chdir(path);
    if (ret != 0) {
        mbedtls_fprintf(stderr, "%s: note: chdir(\"%s\") failed.\n",
                        __func__, path);
    }
    mbedtls_free(path);
}
#else /* MBEDTLS_HAVE_CHDIR */
/* No chdir() or no support for parsing argv[0] on this platform. */
static void try_chdir_if_supported(const char *argv0)
{
    (void) argv0;
    return;
}
#endif /* MBEDTLS_HAVE_CHDIR */

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
static int execute_tests(int argc, const char **argv)
{
    /* Local Configurations and options */
    const char *default_filename = ".\\test_suite_pkcs1_v15.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    size_t testfile_count = 0;
    int option_verbose = 0;
    size_t function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    size_t testfile_index, i, cnt;
    int ret;
    unsigned total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    /* Store for processed integer params. */
    mbedtls_test_argument_t int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */
    const char *outcome_file_name = getenv("MBEDTLS_TEST_OUTCOME_FILE");
    FILE *outcome_file = NULL;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init();
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset(&pointer, 0, sizeof(void *));
    if (pointer != NULL) {
        mbedtls_fprintf(stderr, "all-bits-zero is not a NULL pointer\n");
        return 1;
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if (run_test_snprintf() != 0) {
        mbedtls_fprintf(stderr, "the snprintf implementation is broken\n");
        return 1;
    }

    if (outcome_file_name != NULL && *outcome_file_name != '\0') {
        outcome_file = fopen(outcome_file_name, "a");
        if (outcome_file == NULL) {
            mbedtls_fprintf(stderr, "Unable to open outcome file. Continuing anyway.\n");
        }
    }

    while (arg_index < argc) {
        next_arg = argv[arg_index];

        if (strcmp(next_arg, "--verbose") == 0 ||
            strcmp(next_arg, "-v") == 0) {
            option_verbose = 1;
        } else if (strcmp(next_arg, "--help") == 0 ||
                   strcmp(next_arg, "-h") == 0) {
            mbedtls_fprintf(stdout, USAGE);
            mbedtls_exit(EXIT_SUCCESS);
        } else {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[arg_index];
            testfile_count = argc - arg_index;
            break;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if (test_files == NULL || testfile_count == 0) {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    mbedtls_test_info_reset();

    /* Now begin to execute the tests in the testfiles */
    for (testfile_index = 0;
         testfile_index < testfile_count;
         testfile_index++) {
        size_t unmet_dep_count = 0;
        int unmet_dependencies[20];
        int missing_unmet_dependencies = 0;

        test_filename = test_files[testfile_index];

        file = fopen(test_filename, "r");
        if (file == NULL) {
            mbedtls_fprintf(stderr, "Failed to open test file: %s\n",
                            test_filename);
            if (outcome_file != NULL) {
                fclose(outcome_file);
            }
            return 1;
        }

        while (!feof(file)) {
            if (unmet_dep_count > 0) {
                mbedtls_fprintf(stderr,
                                "FATAL: Dep count larger than zero at start of loop\n");
                mbedtls_exit(MBEDTLS_EXIT_FAILURE);
            }
            unmet_dep_count = 0;
            missing_unmet_dependencies = 0;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            mbedtls_fprintf(stdout, "%s%.66s",
                            mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_FAILED ?
                            "\n" : "", buf);
            mbedtls_fprintf(stdout, " ");
            for (i = strlen(buf) + 1; i < 67; i++) {
                mbedtls_fprintf(stdout, ".");
            }
            mbedtls_fprintf(stdout, " ");
            fflush(stdout);
            write_outcome_entry(outcome_file, argv[0], buf);

            total_tests++;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            cnt = parse_arguments(buf, strlen(buf), params,
                                  sizeof(params) / sizeof(params[0]));

            if (strcmp(params[0], "depends_on") == 0) {
                for (i = 1; i < cnt; i++) {
                    int dep_id = strtol(params[i], NULL, 10);
                    if (dep_check(dep_id) != DEPENDENCY_SUPPORTED) {
                        if (unmet_dep_count <
                            ARRAY_LENGTH(unmet_dependencies)) {
                            unmet_dependencies[unmet_dep_count] = dep_id;
                            unmet_dep_count++;
                        } else {
                            missing_unmet_dependencies = 1;
                        }
                    }
                }

                if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                    break;
                }
                cnt = parse_arguments(buf, strlen(buf), params,
                                      sizeof(params) / sizeof(params[0]));
            }

            // If there are no unmet dependencies execute the test
            if (unmet_dep_count == 0) {
                mbedtls_test_info_reset();

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if (!option_verbose) {
                    stdout_fd = redirect_output(stdout, "/dev/null");
                    if (stdout_fd == -1) {
                        /* Redirection has failed with no stdout so exit */
                        exit(1);
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtoul(params[0], NULL, 10);
                if ((ret = check_test(function_id)) == DISPATCH_TEST_SUCCESS) {
                    ret = convert_params(cnt - 1, params + 1, int_params);
                    if (DISPATCH_TEST_SUCCESS == ret) {
                        ret = dispatch_test(function_id, (void **) (params + 1));
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if (!option_verbose && restore_output(stdout, stdout_fd)) {
                    /* Redirection has failed with no stdout so exit */
                    exit(1);
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            write_outcome_result(outcome_file,
                                 unmet_dep_count, unmet_dependencies,
                                 missing_unmet_dependencies,
                                 ret);
            if (unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE) {
                total_skipped++;
                mbedtls_fprintf(stdout, "----");

                if (1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE) {
                    mbedtls_fprintf(stdout, "\n   Test Suite not enabled");
                }

                if (1 == option_verbose && unmet_dep_count > 0) {
                    mbedtls_fprintf(stdout, "\n   Unmet dependencies: ");
                    for (i = 0; i < unmet_dep_count; i++) {
                        mbedtls_fprintf(stdout, "%d ",
                                        unmet_dependencies[i]);
                    }
                    if (missing_unmet_dependencies) {
                        mbedtls_fprintf(stdout, "...");
                    }
                }
                mbedtls_fprintf(stdout, "\n");
                fflush(stdout);

                unmet_dep_count = 0;
                missing_unmet_dependencies = 0;
            } else if (ret == DISPATCH_TEST_SUCCESS) {
                if (mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_SUCCESS) {
                    mbedtls_fprintf(stdout, "PASS\n");
                } else if (mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_SKIPPED) {
                    mbedtls_fprintf(stdout, "----\n");
                    total_skipped++;
                } else {
                    char line_buffer[MBEDTLS_TEST_LINE_LENGTH];

                    total_errors++;
                    mbedtls_fprintf(stdout, "FAILED\n");
                    mbedtls_fprintf(stdout, "  %s\n  at ",
                                    mbedtls_test_get_test());
                    if (mbedtls_test_get_step() != (unsigned long) (-1)) {
                        mbedtls_fprintf(stdout, "step %lu, ",
                                        mbedtls_test_get_step());
                    }
                    mbedtls_fprintf(stdout, "line %d, %s",
                                    mbedtls_test_get_line_no(),
                                    mbedtls_get_test_filename());

                    mbedtls_test_get_line1(line_buffer);
                    if (line_buffer[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s", line_buffer);
                    }
                    mbedtls_test_get_line2(line_buffer);
                    if (line_buffer[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s", line_buffer);
                    }
                }
                fflush(stdout);
            } else if (ret == DISPATCH_INVALID_TEST_DATA) {
                mbedtls_fprintf(stderr, "FAILED: FATAL PARSE ERROR\n");
                fclose(file);
                mbedtls_exit(2);
            } else if (ret == DISPATCH_TEST_FN_NOT_FOUND) {
                mbedtls_fprintf(stderr, "FAILED: FATAL TEST FUNCTION NOT FOUND\n");
                fclose(file);
                mbedtls_exit(2);
            } else {
                total_errors++;
            }
        }
        fclose(file);
    }

    if (outcome_file != NULL) {
        fclose(outcome_file);
    }

    mbedtls_fprintf(stdout,
                    "\n----------------------------------------------------------------------------\n\n");
    if (total_errors == 0) {
        mbedtls_fprintf(stdout, "PASSED");
    } else {
        mbedtls_fprintf(stdout, "FAILED");
    }

    mbedtls_fprintf(stdout, " (%u / %u tests (%u skipped))\n",
                    total_tests - total_errors, total_tests, total_skipped);

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_end();
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    return total_errors != 0;
}


#line 217 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main(int argc, const char *argv[])
{
#if defined(MBEDTLS_TEST_HOOKS)
    extern void (*mbedtls_test_hook_test_fail)(const char *test, int line, const char *file);
    mbedtls_test_hook_test_fail = &mbedtls_test_fail;
#if defined(MBEDTLS_ERROR_C)
    mbedtls_test_hook_error_add = &mbedtls_test_err_add_check;
#endif
#endif

    /* Try changing to the directory containing the executable, if
     * using the default data file. This allows running the executable
     * from another directory (e.g. the project root) and still access
     * the .datax file as well as data files used by test cases
     * (typically from framework/data_files).
     *
     * Note that we do this before the platform setup (which may access
     * files such as a random seed). We also do this before accessing
     * test-specific files such as the outcome file, which is arguably
     * not desirable and should be fixed later.
     */
    if (argc == 1) {
        try_chdir_if_supported(argv[0]);
    }

    int ret = mbedtls_test_platform_setup();
    if (ret != 0) {
        mbedtls_fprintf(stderr,
                        "FATAL: Failed to initialize platform - error %d\n",
                        ret);
        return -1;
    }

    ret = execute_tests(argc, argv);
    mbedtls_test_platform_teardown();
    return ret;
}
