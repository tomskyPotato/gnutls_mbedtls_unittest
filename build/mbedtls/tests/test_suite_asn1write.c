#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : .\test_suite_asn1write.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/main_test.function
 *      Platform code file  : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/host_test.function
 *      Helper file         : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/helpers.function
 *      Test suite file     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function
 *      Test suite data     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.data
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

#if defined(MBEDTLS_ASN1_WRITE_C)
#line 2 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
#include "mbedtls/asn1write.h"

#define GUARD_LEN 4
#define GUARD_VAL 0x2a

typedef struct {
    unsigned char *output;
    unsigned char *start;
    unsigned char *end;
    unsigned char *p;
    size_t size;
} generic_write_data_t;

static int generic_write_start_step(generic_write_data_t *data)
{
    mbedtls_test_set_step(data->size);
    mbedtls_free(data->output);
    data->output = NULL;
    TEST_CALLOC(data->output, data->size == 0 ? 1 : data->size);
    data->end = data->output + data->size;
    data->p = data->end;
    data->start = data->end - data->size;
    return 1;
exit:
    return 0;
}

static int generic_write_finish_step(generic_write_data_t *data,
                                     const data_t *expected, int ret)
{
    int ok = 0;

    if (data->size < expected->len) {
        TEST_EQUAL(ret, MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
    } else {
        TEST_EQUAL(ret, data->end - data->p);
        TEST_ASSERT(data->p >= data->start);
        TEST_ASSERT(data->p <= data->end);
        TEST_MEMORY_COMPARE(data->p, (size_t) (data->end - data->p),
                            expected->x, expected->len);
    }
    ok = 1;

exit:
    return ok;
}

#line 57 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_null(data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_null(&data.p, data.start);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
        /* There's no parsing function for NULL. */
    }

exit:
    mbedtls_free(data.output);
}

static void test_mbedtls_asn1_write_null_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_mbedtls_asn1_write_null( &data0 );
}
#line 79 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_bool(int val, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_bool(&data.p, data.start, val);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
#if defined(MBEDTLS_ASN1_PARSE_C)
        if (ret >= 0) {
            int read = 0xdeadbeef;
            TEST_EQUAL(mbedtls_asn1_get_bool(&data.p, data.end, &read), 0);
            TEST_EQUAL(val, read);
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
    }

exit:
    mbedtls_free(data.output);
}

static void test_mbedtls_asn1_write_bool_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_mbedtls_asn1_write_bool( ((mbedtls_test_argument_t *) params[0])->sint, &data1 );
}
#line 107 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_int(int val, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_int(&data.p, data.start, val);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
#if defined(MBEDTLS_ASN1_PARSE_C)
        if (ret >= 0) {
            int read = 0xdeadbeef;
            TEST_EQUAL(mbedtls_asn1_get_int(&data.p, data.end, &read), 0);
            TEST_EQUAL(val, read);
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
    }

exit:
    mbedtls_free(data.output);
}

static void test_mbedtls_asn1_write_int_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_mbedtls_asn1_write_int( ((mbedtls_test_argument_t *) params[0])->sint, &data1 );
}
#line 136 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_enum(int val, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_enum(&data.p, data.start, val);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
#if defined(MBEDTLS_ASN1_PARSE_C)
        if (ret >= 0) {
            int read = 0xdeadbeef;
            TEST_EQUAL(mbedtls_asn1_get_enum(&data.p, data.end, &read), 0);
            TEST_EQUAL(val, read);
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
    }

exit:
    mbedtls_free(data.output);
}

static void test_mbedtls_asn1_write_enum_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_mbedtls_asn1_write_enum( ((mbedtls_test_argument_t *) params[0])->sint, &data1 );
}
#if defined(MBEDTLS_BIGNUM_C)
#line 164 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_mpi(data_t *val, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    mbedtls_mpi mpi, read;
    int ret;

    mbedtls_mpi_init(&mpi);
    mbedtls_mpi_init(&read);
    TEST_ASSERT(mbedtls_mpi_read_binary(&mpi, val->x, val->len) == 0);

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_mpi(&data.p, data.start, &mpi);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
#if defined(MBEDTLS_ASN1_PARSE_C)
        if (ret >= 0) {
            TEST_EQUAL(mbedtls_asn1_get_mpi(&data.p, data.end, &read), 0);
            TEST_EQUAL(0, mbedtls_mpi_cmp_mpi(&mpi, &read));
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
        /* Skip some intermediate lengths, they're boring. */
        if (expected->len > 10 && data.size == 8) {
            data.size = expected->len - 2;
        }
    }

exit:
    mbedtls_mpi_free(&mpi);
    mbedtls_mpi_free(&read);
    mbedtls_free(data.output);
}

static void test_mbedtls_asn1_write_mpi_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_mbedtls_asn1_write_mpi( &data0, &data2 );
}
#endif /* MBEDTLS_BIGNUM_C */
#line 202 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_string(int tag, data_t *content, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        switch (tag) {
            case MBEDTLS_ASN1_OCTET_STRING:
                ret = mbedtls_asn1_write_octet_string(
                    &data.p, data.start, content->x, content->len);
                break;
            case MBEDTLS_ASN1_OID:
                ret = mbedtls_asn1_write_oid(
                    &data.p, data.start,
                    (const char *) content->x, content->len);
                break;
            case MBEDTLS_ASN1_UTF8_STRING:
                ret = mbedtls_asn1_write_utf8_string(
                    &data.p, data.start,
                    (const char *) content->x, content->len);
                break;
            case MBEDTLS_ASN1_PRINTABLE_STRING:
                ret = mbedtls_asn1_write_printable_string(
                    &data.p, data.start,
                    (const char *) content->x, content->len);
                break;
            case MBEDTLS_ASN1_IA5_STRING:
                ret = mbedtls_asn1_write_ia5_string(
                    &data.p, data.start,
                    (const char *) content->x, content->len);
                break;
            default:
                ret = mbedtls_asn1_write_tagged_string(
                    &data.p, data.start, tag,
                    (const char *) content->x, content->len);
        }
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
        /* There's no parsing function for octet or character strings. */
        /* Skip some intermediate lengths, they're boring. */
        if (expected->len > 10 && data.size == 8) {
            data.size = expected->len - 2;
        }
    }

exit:
    mbedtls_free(data.output);
}

static void test_mbedtls_asn1_write_string_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};

    test_mbedtls_asn1_write_string( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3 );
}
#line 257 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_algorithm_identifier(data_t *oid,
                                             int par_len,
                                             data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;
#if defined(MBEDTLS_ASN1_PARSE_C)
    unsigned char *buf_complete = NULL;
#endif /* MBEDTLS_ASN1_PARSE_C */

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_algorithm_identifier(
            &data.p, data.start,
            (const char *) oid->x, oid->len, par_len);
        /* If params_len != 0, mbedtls_asn1_write_algorithm_identifier()
         * assumes that the parameters are already present in the buffer
         * and returns a length that accounts for this, but our test
         * data omits the parameters. */
        if (ret >= 0) {
            ret -= par_len;
        }
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }

#if defined(MBEDTLS_ASN1_PARSE_C)
        /* Only do a parse-back test if the parameters aren't too large for
         * a small-heap environment. The boundary is somewhat arbitrary. */
        if (ret >= 0 && par_len <= 1234) {
            mbedtls_asn1_buf alg = { 0, 0, NULL };
            mbedtls_asn1_buf params = { 0, 0, NULL };
            /* The writing function doesn't write the parameters unless
             * they're null: it only takes their length as input. But the
             * parsing function requires the parameters to be present.
             * Thus make up parameters. */
            size_t data_len = data.end - data.p;
            size_t len_complete = data_len + par_len;
            unsigned char expected_params_tag;
            size_t expected_params_len;
            TEST_CALLOC(buf_complete, len_complete);
            unsigned char *end_complete = buf_complete + len_complete;
            memcpy(buf_complete, data.p, data_len);
            if (par_len == 0) {
                /* mbedtls_asn1_write_algorithm_identifier() wrote a NULL */
                expected_params_tag = 0x05;
                expected_params_len = 0;
            } else if (par_len >= 2 && par_len < 2 + 128) {
                /* Write an OCTET STRING with a short length encoding */
                expected_params_tag = buf_complete[data_len] = 0x04;
                expected_params_len = par_len - 2;
                buf_complete[data_len + 1] = (unsigned char) expected_params_len;
            } else if (par_len >= 4 + 128 && par_len < 3 + 256 * 256) {
                /* Write an OCTET STRING with a two-byte length encoding */
                expected_params_tag = buf_complete[data_len] = 0x04;
                expected_params_len = par_len - 4;
                buf_complete[data_len + 1] = 0x82;
                buf_complete[data_len + 2] = (unsigned char) (expected_params_len >> 8);
                buf_complete[data_len + 3] = (unsigned char) (expected_params_len);
            } else {
                TEST_FAIL("Bad test data: invalid length of ASN.1 element");
            }
            unsigned char *p = buf_complete;
            TEST_EQUAL(mbedtls_asn1_get_alg(&p, end_complete,
                                            &alg, &params), 0);
            TEST_EQUAL(alg.tag, MBEDTLS_ASN1_OID);
            TEST_MEMORY_COMPARE(alg.p, alg.len, oid->x, oid->len);
            TEST_EQUAL(params.tag, expected_params_tag);
            TEST_EQUAL(params.len, expected_params_len);
            mbedtls_free(buf_complete);
            buf_complete = NULL;
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
    }

exit:
    mbedtls_free(data.output);
#if defined(MBEDTLS_ASN1_PARSE_C)
    mbedtls_free(buf_complete);
#endif /* MBEDTLS_ASN1_PARSE_C */
}

static void test_mbedtls_asn1_write_algorithm_identifier_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};

    test_mbedtls_asn1_write_algorithm_identifier( &data0, ((mbedtls_test_argument_t *) params[2])->sint, &data3 );
}
#if defined(MBEDTLS_ASN1_PARSE_C)
#line 343 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_mbedtls_asn1_write_len(int len, data_t *asn1, int buf_len,
                            int result)
{
    int ret;
    unsigned char buf[150];
    unsigned char *p;
    size_t i;
    size_t read_len;

    memset(buf, GUARD_VAL, sizeof(buf));

    p = buf + GUARD_LEN + buf_len;

    ret = mbedtls_asn1_write_len(&p, buf + GUARD_LEN, (size_t) len);

    TEST_ASSERT(ret == result);

    /* Check for buffer overwrite on both sides */
    for (i = 0; i < GUARD_LEN; i++) {
        TEST_ASSERT(buf[i] == GUARD_VAL);
        TEST_ASSERT(buf[GUARD_LEN + buf_len + i] == GUARD_VAL);
    }

    if (result >= 0) {
        TEST_ASSERT(p + asn1->len == buf + GUARD_LEN + buf_len);

        TEST_ASSERT(memcmp(p, asn1->x, asn1->len) == 0);

        /* Read back with mbedtls_asn1_get_len() to check */
        ret = mbedtls_asn1_get_len(&p, buf + GUARD_LEN + buf_len, &read_len);

        if (len == 0) {
            TEST_ASSERT(ret == 0);
        } else {
            /* Return will be MBEDTLS_ERR_ASN1_OUT_OF_DATA because the rest of
             * the buffer is missing
             */
            TEST_ASSERT(ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA);
        }
        TEST_ASSERT(read_len == (size_t) len);
        TEST_ASSERT(p == buf + GUARD_LEN + buf_len);
    }
exit:
    ;
}

static void test_mbedtls_asn1_write_len_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_mbedtls_asn1_write_len( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_ASN1_PARSE_C */
#line 389 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_test_asn1_write_bitstrings(data_t *bitstring, int bits,
                                data_t *expected, int is_named)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;
    int (*func)(unsigned char **p, const unsigned char *start,
                const unsigned char *buf, size_t bits) =
        (is_named ? mbedtls_asn1_write_named_bitstring :
         mbedtls_asn1_write_bitstring);
#if defined(MBEDTLS_ASN1_PARSE_C)
    unsigned char *masked_bitstring = NULL;
#endif /* MBEDTLS_ASN1_PARSE_C */

    /* The API expects `bitstring->x` to contain `bits` bits. */
    size_t byte_length = (bits + 7) / 8;
    TEST_ASSERT(bitstring->len >= byte_length);

#if defined(MBEDTLS_ASN1_PARSE_C)
    TEST_CALLOC(masked_bitstring, byte_length);
    if (byte_length != 0) {
        memcpy(masked_bitstring, bitstring->x, byte_length);
        if (bits % 8 != 0) {
            masked_bitstring[byte_length - 1] &= ~(0xff >> (bits % 8));
        }
    }
    size_t value_bits = bits;
    if (is_named) {
        /* In a named bit string, all trailing 0 bits are removed. */
        while (byte_length > 0 && masked_bitstring[byte_length - 1] == 0) {
            --byte_length;
        }
        value_bits = 8 * byte_length;
        if (byte_length > 0) {
            unsigned char last_byte = masked_bitstring[byte_length - 1];
            for (unsigned b = 1; b < 0xff && (last_byte & b) == 0; b <<= 1) {
                --value_bits;
            }
        }
    }
#endif /* MBEDTLS_ASN1_PARSE_C */

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = (*func)(&data.p, data.start, bitstring->x, bits);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
#if defined(MBEDTLS_ASN1_PARSE_C)
        if (ret >= 0) {
            mbedtls_asn1_bitstring read = { 0, 0, NULL };
            TEST_EQUAL(mbedtls_asn1_get_bitstring(&data.p, data.end,
                                                  &read), 0);
            TEST_MEMORY_COMPARE(read.p, read.len,
                                masked_bitstring, byte_length);
            TEST_EQUAL(read.unused_bits, 8 * byte_length - value_bits);
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
    }

exit:
    mbedtls_free(data.output);
#if defined(MBEDTLS_ASN1_PARSE_C)
    mbedtls_free(masked_bitstring);
#endif /* MBEDTLS_ASN1_PARSE_C */
}

static void test_test_asn1_write_bitstrings_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};

    test_test_asn1_write_bitstrings( &data0, ((mbedtls_test_argument_t *) params[2])->sint, &data3, ((mbedtls_test_argument_t *) params[5])->sint );
}
#line 459 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_store_named_data_find(data_t *oid0, data_t *oid1,
                           data_t *oid2, data_t *oid3,
                           data_t *needle, int from, int position)
{
    data_t *oid[4] = { oid0, oid1, oid2, oid3 };
    mbedtls_asn1_named_data nd[] = {
        { { 0x06, 0, NULL }, { 0, 0, NULL }, NULL, 0 },
        { { 0x06, 0, NULL }, { 0, 0, NULL }, NULL, 0 },
        { { 0x06, 0, NULL }, { 0, 0, NULL }, NULL, 0 },
        { { 0x06, 0, NULL }, { 0, 0, NULL }, NULL, 0 },
    };
    mbedtls_asn1_named_data *pointers[ARRAY_LENGTH(nd) + 1];
    size_t i;
    mbedtls_asn1_named_data *head = NULL;
    mbedtls_asn1_named_data *found = NULL;

    for (i = 0; i < ARRAY_LENGTH(nd); i++) {
        pointers[i] = &nd[i];
    }
    pointers[ARRAY_LENGTH(nd)] = NULL;
    for (i = 0; i < ARRAY_LENGTH(nd); i++) {
        TEST_CALLOC(nd[i].oid.p, oid[i]->len);
        memcpy(nd[i].oid.p, oid[i]->x, oid[i]->len);
        nd[i].oid.len = oid[i]->len;
        nd[i].next = pointers[i+1];
    }

    head = pointers[from];
    found = mbedtls_asn1_store_named_data(&head,
                                          (const char *) needle->x,
                                          needle->len,
                                          NULL, 0);

    /* In any case, the existing list structure must be unchanged. */
    for (i = 0; i < ARRAY_LENGTH(nd); i++) {
        TEST_ASSERT(nd[i].next == pointers[i+1]);
    }

    if (position >= 0) {
        /* position should have been found and modified. */
        TEST_ASSERT(head == pointers[from]);
        TEST_ASSERT(found == pointers[position]);
    } else {
        /* A new entry should have been created. */
        TEST_ASSERT(found == head);
        TEST_ASSERT(head->next == pointers[from]);
        for (i = 0; i < ARRAY_LENGTH(nd); i++) {
            TEST_ASSERT(found != &nd[i]);
        }
    }

exit:
    if (found != NULL && found == head && found != pointers[from]) {
        mbedtls_free(found->oid.p);
        mbedtls_free(found);
    }
    for (i = 0; i < ARRAY_LENGTH(nd); i++) {
        mbedtls_free(nd[i].oid.p);
    }
}

static void test_store_named_data_find_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};
    data_t data8 = {(uint8_t *) params[8], ((mbedtls_test_argument_t *) params[9])->len};

    test_store_named_data_find( &data0, &data2, &data4, &data6, &data8, ((mbedtls_test_argument_t *) params[10])->sint, ((mbedtls_test_argument_t *) params[11])->sint );
}
#line 522 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_store_named_data_val_found(int old_len, int new_len)
{
    mbedtls_asn1_named_data nd =
    { { 0x06, 3, (unsigned char *) "OID" }, { 0, 0, NULL }, NULL, 0 };
    mbedtls_asn1_named_data *head = &nd;
    mbedtls_asn1_named_data *found = NULL;
    unsigned char *old_val = NULL;
    unsigned char *new_val = (unsigned char *) "new value";

    if (old_len != 0) {
        TEST_CALLOC(nd.val.p, (size_t) old_len);
        old_val = nd.val.p;
        nd.val.len = old_len;
        memset(old_val, 'x', old_len);
    }
    if (new_len <= 0) {
        new_len = -new_len;
        new_val = NULL;
    }

    found = mbedtls_asn1_store_named_data(&head, "OID", 3,
                                          new_val, new_len);
    TEST_ASSERT(head == &nd);
    TEST_ASSERT(found == head);

    if (new_val != NULL) {
        TEST_MEMORY_COMPARE(found->val.p, found->val.len,
                            new_val, (size_t) new_len);
    }
    if (new_len == 0) {
        TEST_ASSERT(found->val.p == NULL);
    } else if (new_len == old_len) {
        TEST_ASSERT(found->val.p == old_val);
    } else {
        TEST_ASSERT(found->val.p != old_val);
    }

exit:
    mbedtls_free(nd.val.p);
}

static void test_store_named_data_val_found_wrapper( void ** params )
{

    test_store_named_data_val_found( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint );
}
#line 565 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_asn1write.function"
static void test_store_named_data_val_new(int new_len, int set_new_val)
{
    mbedtls_asn1_named_data *head = NULL;
    mbedtls_asn1_named_data *found = NULL;
    const unsigned char *oid = (unsigned char *) "OID";
    size_t oid_len = strlen((const char *) oid);
    const unsigned char *new_val = (unsigned char *) "new value";

    if (set_new_val == 0) {
        new_val = NULL;
    }

    found = mbedtls_asn1_store_named_data(&head,
                                          (const char *) oid, oid_len,
                                          new_val, (size_t) new_len);
    TEST_ASSERT(found != NULL);
    TEST_ASSERT(found == head);
    TEST_ASSERT(found->oid.p != oid);
    TEST_MEMORY_COMPARE(found->oid.p, found->oid.len, oid, oid_len);
    if (new_len == 0) {
        TEST_ASSERT(found->val.p == NULL);
    } else if (new_val == NULL) {
        TEST_ASSERT(found->val.p != NULL);
    } else {
        TEST_ASSERT(found->val.p != new_val);
        TEST_MEMORY_COMPARE(found->val.p, found->val.len,
                            new_val, (size_t) new_len);
    }

exit:
    if (found != NULL) {
        mbedtls_free(found->oid.p);
        mbedtls_free(found->val.p);
    }
    mbedtls_free(found);
}

static void test_store_named_data_val_new_wrapper( void ** params )
{

    test_store_named_data_val_new( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint );
}
#endif /* MBEDTLS_ASN1_WRITE_C */


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
    
#if defined(MBEDTLS_ASN1_WRITE_C)

        case 0:
            {
                *out_value = MBEDTLS_ASN1_OCTET_STRING;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_ASN1_UTF8_STRING;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ASN1_PRINTABLE_STRING;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ASN1_IA5_STRING;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ASN1_IA5_STRING | MBEDTLS_ASN1_CONTEXT_SPECIFIC;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_ASN1_OID;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
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
    
#if defined(MBEDTLS_ASN1_WRITE_C)

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

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_null_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_bool_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_int_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_enum_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_ASN1_WRITE_C) && defined(MBEDTLS_BIGNUM_C)
    test_mbedtls_asn1_write_mpi_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_string_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_mbedtls_asn1_write_algorithm_identifier_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_ASN1_WRITE_C) && defined(MBEDTLS_ASN1_PARSE_C)
    test_mbedtls_asn1_write_len_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_test_asn1_write_bitstrings_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_store_named_data_find_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_store_named_data_val_found_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_ASN1_WRITE_C)
    test_store_named_data_val_new_wrapper,
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
    const char *default_filename = ".\\test_suite_asn1write.datax";
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
