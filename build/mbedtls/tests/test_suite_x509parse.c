#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : .\test_suite_x509parse.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/main_test.function
 *      Platform code file  : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/host_test.function
 *      Helper file         : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/helpers.function
 *      Test suite file     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function
 *      Test suite data     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.data
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

#line 2 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_csr.h"
#include "x509_internal.h"
#include "mbedtls/pem.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "string.h"

#if MBEDTLS_X509_MAX_INTERMEDIATE_CA > 19
#error "The value of MBEDTLS_X509_MAX_INTERMEDIATE_C is larger \
    than the current threshold 19. To test larger values, please \
    adapt the script framework/data_files/dir-max/long.sh."
#endif

/* Test-only profile allowing all digests, PK algorithms, and curves. */
const mbedtls_x509_crt_profile profile_all =
{
    0xFFFFFFFF, /* Any MD        */
    0xFFFFFFFF, /* Any PK alg    */
    0xFFFFFFFF, /* Any curve     */
    1024,
};

/* Profile for backward compatibility. Allows SHA-1, unlike the default
   profile. */
const mbedtls_x509_crt_profile compat_profile =
{
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_RIPEMD160) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA224) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
    0xFFFFFFFF, /* Any PK alg    */
    0xFFFFFFFF, /* Any curve     */
    1024,
};

const mbedtls_x509_crt_profile profile_rsa3072 =
{
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
    MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_RSA),
    0,
    3072,
};

const mbedtls_x509_crt_profile profile_sha512 =
{
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
    0xFFFFFFFF, /* Any PK alg    */
    0xFFFFFFFF, /* Any curve     */
    1024,
};

#if defined(MBEDTLS_X509_CRT_PARSE_C)

#if defined(MBEDTLS_FS_IO)
static int verify_none(void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags)
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags |= MBEDTLS_X509_BADCERT_OTHER;

    return 0;
}

static int verify_all(void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags)
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags = 0;

    return 0;
}

#if defined(MBEDTLS_X509_CRL_PARSE_C) && \
    defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
static int ca_callback_fail(void *data, mbedtls_x509_crt const *child,
                            mbedtls_x509_crt **candidates)
{
    ((void) data);
    ((void) child);
    ((void) candidates);

    return -1;
}

static int ca_callback(void *data, mbedtls_x509_crt const *child,
                       mbedtls_x509_crt **candidates)
{
    int ret = 0;
    mbedtls_x509_crt *ca = (mbedtls_x509_crt *) data;
    mbedtls_x509_crt *first;

    /* This is a test-only implementation of the CA callback
     * which always returns the entire list of trusted certificates.
     * Production implementations managing a large number of CAs
     * should use an efficient presentation and lookup for the
     * set of trusted certificates (such as a hashtable) and only
     * return those trusted certificates which satisfy basic
     * parental checks, such as the matching of child `Issuer`
     * and parent `Subject` field. */
    ((void) child);

    first = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
    if (first == NULL) {
        ret = -1;
        goto exit;
    }
    mbedtls_x509_crt_init(first);

    if (mbedtls_x509_crt_parse_der(first, ca->raw.p, ca->raw.len) != 0) {
        ret = -1;
        goto exit;
    }

    while (ca->next != NULL) {
        ca = ca->next;
        if (mbedtls_x509_crt_parse_der(first, ca->raw.p, ca->raw.len) != 0) {
            ret = -1;
            goto exit;
        }
    }

exit:

    if (ret != 0) {
        mbedtls_x509_crt_free(first);
        mbedtls_free(first);
        first = NULL;
    }

    *candidates = first;
    return ret;
}
#endif /* MBEDTLS_X509_CRL_PARSE_C && MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */

static int verify_fatal(void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags)
{
    int *levels = (int *) data;

    ((void) crt);
    ((void) certificate_depth);

    /* Simulate a fatal error in the callback */
    if (*levels & (1 << certificate_depth)) {
        *flags |= (1 << certificate_depth);
        return -1 - certificate_depth;
    }

    return 0;
}

/* strsep() not available on Windows */
static char *mystrsep(char **stringp, const char *delim)
{
    const char *p;
    char *ret = *stringp;

    if (*stringp == NULL) {
        return NULL;
    }

    for (;; (*stringp)++) {
        if (**stringp == '\0') {
            *stringp = NULL;
            goto done;
        }

        for (p = delim; *p != '\0'; p++) {
            if (**stringp == *p) {
                **stringp = '\0';
                (*stringp)++;
                goto done;
            }
        }
    }

done:
    return ret;
}

typedef struct {
    char buf[512];
    char *p;
} verify_print_context;

static void verify_print_init(verify_print_context *ctx)
{
    memset(ctx, 0, sizeof(verify_print_context));
    ctx->p = ctx->buf;
}

static int verify_print(void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags)
{
    int ret;
    verify_print_context *ctx = (verify_print_context *) data;
    char *p = ctx->p;
    size_t n = ctx->buf + sizeof(ctx->buf) - ctx->p;
    ((void) flags);

    ret = mbedtls_snprintf(p, n, "depth %d - serial ", certificate_depth);
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_serial_gets(p, n, &crt->serial);
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf(p, n, " - subject ");
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_dn_gets(p, n, &crt->subject);
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf(p, n, " - flags 0x%08x\n", *flags);
    MBEDTLS_X509_SAFE_SNPRINTF;

    ctx->p = p;

    return 0;
}

static int verify_parse_san(mbedtls_x509_subject_alternative_name *san,
                            char **buf, size_t *size)
{
    int ret;
    size_t i;
    char *p = *buf;
    size_t n = *size;

    ret = mbedtls_snprintf(p, n, "type : %d", san->type);
    MBEDTLS_X509_SAFE_SNPRINTF;

    switch (san->type) {
        case (MBEDTLS_X509_SAN_OTHER_NAME):
            ret = mbedtls_snprintf(p, n, "\notherName :");
            MBEDTLS_X509_SAFE_SNPRINTF;

            if (MBEDTLS_OID_CMP(MBEDTLS_OID_ON_HW_MODULE_NAME,
                                &san->san.other_name.type_id) == 0) {
                ret = mbedtls_snprintf(p, n, " hardware module name :");
                MBEDTLS_X509_SAFE_SNPRINTF;
                ret = mbedtls_snprintf(p, n, " hardware type : ");
                MBEDTLS_X509_SAFE_SNPRINTF;

                ret = mbedtls_oid_get_numeric_string(p,
                                                     n,
                                                     &san->san.other_name.value.hardware_module_name
                                                     .oid);
                MBEDTLS_X509_SAFE_SNPRINTF;

                ret = mbedtls_snprintf(p, n, ", hardware serial number : ");
                MBEDTLS_X509_SAFE_SNPRINTF;

                for (i = 0; i < san->san.other_name.value.hardware_module_name.val.len; i++) {
                    ret = mbedtls_snprintf(p,
                                           n,
                                           "%02X",
                                           san->san.other_name.value.hardware_module_name.val.p[i]);
                    MBEDTLS_X509_SAFE_SNPRINTF;
                }
            }
            break;/* MBEDTLS_OID_ON_HW_MODULE_NAME */
        case (MBEDTLS_X509_SAN_DNS_NAME):
            ret = mbedtls_snprintf(p, n, "\ndNSName : ");
            MBEDTLS_X509_SAFE_SNPRINTF;
            if (san->san.unstructured_name.len >= n) {
                *p = '\0';
                return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            }
            n -= san->san.unstructured_name.len;
            for (i = 0; i < san->san.unstructured_name.len; i++) {
                *p++ = san->san.unstructured_name.p[i];
            }
            break;/* MBEDTLS_X509_SAN_DNS_NAME */
        case (MBEDTLS_X509_SAN_RFC822_NAME):
            ret = mbedtls_snprintf(p, n, "\nrfc822Name : ");
            MBEDTLS_X509_SAFE_SNPRINTF;
            if (san->san.unstructured_name.len >= n) {
                *p = '\0';
                return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            }
            n -= san->san.unstructured_name.len;
            for (i = 0; i < san->san.unstructured_name.len; i++) {
                *p++ = san->san.unstructured_name.p[i];
            }
            break;/* MBEDTLS_X509_SAN_RFC822_NAME */
        case (MBEDTLS_X509_SAN_DIRECTORY_NAME):
            ret = mbedtls_snprintf(p, n, "\ndirectoryName : ");
            MBEDTLS_X509_SAFE_SNPRINTF;
            ret = mbedtls_x509_dn_gets(p, n, &san->san.directory_name);
            if (ret < 0) {
                return ret;
            }

            p += ret;
            n -= ret;
            break;/* MBEDTLS_X509_SAN_DIRECTORY_NAME */
        default:
            /*
             * Should not happen.
             */
            return -1;
    }
    ret = mbedtls_snprintf(p, n, "\n");
    MBEDTLS_X509_SAFE_SNPRINTF;

    *size = n;
    *buf = p;

    return 0;
}
#endif /* MBEDTLS_FS_IO */

static int parse_crt_ext_cb(void *p_ctx, mbedtls_x509_crt const *crt, mbedtls_x509_buf const *oid,
                            int critical, const unsigned char *cp, const unsigned char *end)
{
    (void) crt;
    (void) critical;
    mbedtls_x509_buf *new_oid = (mbedtls_x509_buf *) p_ctx;
    if (oid->tag == MBEDTLS_ASN1_OID &&
        MBEDTLS_OID_CMP(MBEDTLS_OID_CERTIFICATE_POLICIES, oid) == 0) {
        /* Handle unknown certificate policy */
        int ret, parse_ret = 0;
        size_t len;
        unsigned char **p = (unsigned char **) &cp;

        /* Get main sequence tag */
        ret = mbedtls_asn1_get_tag(p, end, &len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        if (*p + len != end) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }

        /*
         * Cannot be an empty sequence.
         */
        if (len == 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }

        while (*p < end) {
            const unsigned char *policy_end;

            /*
             * Get the policy sequence
             */
            if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) !=
                0) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
            }

            policy_end = *p + len;

            if ((ret = mbedtls_asn1_get_tag(p, policy_end, &len,
                                            MBEDTLS_ASN1_OID)) != 0) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
            }

            /*
             * Recognize exclusively the policy with OID 1
             */
            if (len != 1 || *p[0] != 1) {
                parse_ret = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
            }

            *p += len;

            /*
             * If there is an optional qualifier, then *p < policy_end
             * Check the Qualifier len to verify it doesn't exceed policy_end.
             */
            if (*p < policy_end) {
                if ((ret = mbedtls_asn1_get_tag(p, policy_end, &len,
                                                MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE)) != 0) {
                    return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
                }
                /*
                 * Skip the optional policy qualifiers.
                 */
                *p += len;
            }

            if (*p != policy_end) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                         MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
            }
        }

        if (*p != end) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }

        return parse_ret;
    } else if (new_oid != NULL && new_oid->tag == oid->tag && new_oid->len == oid->len &&
               memcmp(new_oid->p, oid->p, oid->len) == 0) {
        return 0;
    } else {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_X509_CSR_PARSE_C) && \
    !defined(MBEDTLS_X509_REMOVE_INFO)
static int parse_csr_ext_accept_cb(void *p_ctx,
                                   mbedtls_x509_csr const *csr,
                                   mbedtls_x509_buf const *oid,
                                   int critical,
                                   const unsigned char *cp,
                                   const unsigned char *end)
{
    (void) p_ctx;
    (void) csr;
    (void) oid;
    (void) critical;
    (void) cp;
    (void) end;

    return 0;
}

static int parse_csr_ext_reject_cb(void *p_ctx,
                                   mbedtls_x509_csr const *csr,
                                   mbedtls_x509_buf const *oid,
                                   int critical,
                                   const unsigned char *cp,
                                   const unsigned char *end)
{
    (void) p_ctx;
    (void) csr;
    (void) oid;
    (void) critical;
    (void) cp;
    (void) end;

    return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                             MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
}
#endif /* MBEDTLS_X509_CSR_PARSE_C && !MBEDTLS_X509_REMOVE_INFO */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 463 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_accessor_ext_types(int ext_type, int has_ext_type)
{
    mbedtls_x509_crt crt;
    int expected_result = ext_type & has_ext_type;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    crt.ext_types = ext_type;

    TEST_EQUAL(mbedtls_x509_crt_has_ext_type(&crt, has_ext_type), expected_result);

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509_accessor_ext_types_wrapper( void ** params )
{

    test_x509_accessor_ext_types( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_TEST_HOOKS)
#line 482 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_crt_parse_cn_inet_pton(const char *cn, data_t *exp, int ref_ret)
{
    uint32_t addr[4];
    size_t addrlen = mbedtls_x509_crt_parse_cn_inet_pton(cn, addr);
    TEST_EQUAL(addrlen, (size_t) ref_ret);

    if (addrlen) {
        TEST_MEMORY_COMPARE(exp->x, exp->len, addr, addrlen);
    }
exit:
    ;
}

static void test_x509_crt_parse_cn_inet_pton_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_x509_crt_parse_cn_inet_pton( (char *) params[0], &data1, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_TEST_HOOKS */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 495 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_parse_san(char *crt_file, char *result_str, int parse_result)
{
    int ret;
    mbedtls_x509_crt   crt;
    mbedtls_x509_subject_alternative_name san;
    mbedtls_x509_sequence *cur = NULL;
    char buf[2000];
    char *p = buf;
    size_t n = sizeof(buf);

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();
    memset(buf, 0, 2000);

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), parse_result);

    if (parse_result != 0) {
        goto exit;
    }
    if (crt.ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        cur = &crt.subject_alt_names;
        while (cur != NULL) {
            ret = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
            TEST_ASSERT(ret == 0 || ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE);
            /*
             * If san type not supported, ignore.
             */
            if (ret == 0) {
                ret = verify_parse_san(&san, &p, &n);
                mbedtls_x509_free_subject_alt_name(&san);
                TEST_EQUAL(ret, 0);
            }
            cur = cur->next;
        }
    }

    TEST_EQUAL(strcmp(buf, result_str), 0);

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509_parse_san_wrapper( void ** params )
{

    test_x509_parse_san( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 540 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_cert_info(char *crt_file, char *result_str)
{
    mbedtls_x509_crt   crt;
    char buf[2000];
    int res;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();
    memset(buf, 0, 2000);

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    res = mbedtls_x509_crt_info(buf, 2000, "", &crt);

    TEST_ASSERT(res != -1);
    TEST_ASSERT(res != -2);

    TEST_EQUAL(strcmp(buf, result_str), 0);

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509_cert_info_wrapper( void ** params )
{

    test_x509_cert_info( (char *) params[0], (char *) params[1] );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRL_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 565 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_crl_info(char *crl_file, char *result_str)
{
    mbedtls_x509_crl   crl;
    char buf[2000];
    int res;

    mbedtls_x509_crl_init(&crl);
    USE_PSA_INIT();
    memset(buf, 0, 2000);

    TEST_EQUAL(mbedtls_x509_crl_parse_file(&crl, crl_file), 0);
    res = mbedtls_x509_crl_info(buf, 2000, "", &crl);

    TEST_ASSERT(res != -1);
    TEST_ASSERT(res != -2);

    TEST_EQUAL(strcmp(buf, result_str), 0);

exit:
    mbedtls_x509_crl_free(&crl);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_crl_info_wrapper( void ** params )
{

    test_mbedtls_x509_crl_info( (char *) params[0], (char *) params[1] );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRL_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRL_PARSE_C)
#line 590 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_crl_parse(char *crl_file, int result)
{
    mbedtls_x509_crl   crl;
    char buf[2000];

    mbedtls_x509_crl_init(&crl);
    USE_PSA_INIT();
    memset(buf, 0, 2000);

    TEST_EQUAL(mbedtls_x509_crl_parse_file(&crl, crl_file), result);

exit:
    mbedtls_x509_crl_free(&crl);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_crl_parse_wrapper( void ** params )
{

    test_mbedtls_x509_crl_parse( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint );
}
#endif /* MBEDTLS_X509_CRL_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CSR_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 608 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_csr_info(char *csr_file, char *result_str)
{
    mbedtls_x509_csr   csr;
    char buf[2000];
    int res;

    mbedtls_x509_csr_init(&csr);
    USE_PSA_INIT();
    memset(buf, 0, 2000);

    TEST_EQUAL(mbedtls_x509_csr_parse_file(&csr, csr_file), 0);
    res = mbedtls_x509_csr_info(buf, 2000, "", &csr);

    TEST_ASSERT(res != -1);
    TEST_ASSERT(res != -2);

    TEST_EQUAL(strcmp(buf, result_str), 0);

exit:
    mbedtls_x509_csr_free(&csr);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_csr_info_wrapper( void ** params )
{

    test_mbedtls_x509_csr_info( (char *) params[0], (char *) params[1] );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CSR_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 633 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_verify_info(int flags, char *prefix, char *result_str)
{
    char buf[2000];
    int res;

    USE_PSA_INIT();
    memset(buf, 0, sizeof(buf));

    res = mbedtls_x509_crt_verify_info(buf, sizeof(buf), prefix, flags);

    TEST_ASSERT(res >= 0);

    TEST_EQUAL(strcmp(buf, result_str), 0);

exit:
    USE_PSA_DONE();
}

static void test_x509_verify_info_wrapper( void ** params )
{

    test_x509_verify_info( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2] );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_X509_CRL_PARSE_C)
#if defined(MBEDTLS_ECP_RESTARTABLE)
#if defined(MBEDTLS_ECDSA_C)
#line 653 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_verify_restart(char *crt_file, char *ca_file,
                         int result, int flags_result,
                         int max_ops, int min_restart, int max_restart)
{
    int ret, cnt_restart;
    mbedtls_x509_crt_restart_ctx rs_ctx;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt ca;
    uint32_t flags = 0;

    /*
     * See comments on ecp_test_vect_restart() for op count precision.
     *
     * For reference, with Mbed TLS 2.6 and default settings:
     * - ecdsa_verify() for P-256:  ~  6700
     * - ecdsa_verify() for P-384:  ~ 18800
     * - x509_verify() for server5 -> test-ca2:             ~ 18800
     * - x509_verify() for server10 -> int-ca3 -> int-ca2:  ~ 25500
     */
    mbedtls_x509_crt_restart_init(&rs_ctx);
    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&ca);
    MD_OR_USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    TEST_EQUAL(mbedtls_x509_crt_parse_file(&ca, ca_file), 0);

    mbedtls_ecp_set_max_ops(max_ops);

    cnt_restart = 0;
    do {
        ret = mbedtls_x509_crt_verify_restartable(&crt, &ca, NULL,
                                                  &mbedtls_x509_crt_profile_default, NULL, &flags,
                                                  NULL, NULL, &rs_ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restart);

    TEST_EQUAL(ret, result);
    TEST_EQUAL(flags, (uint32_t) flags_result);

    TEST_ASSERT(cnt_restart >= min_restart);
    TEST_ASSERT(cnt_restart <= max_restart);

    /* Do we leak memory when aborting? */
    ret = mbedtls_x509_crt_verify_restartable(&crt, &ca, NULL,
                                              &mbedtls_x509_crt_profile_default, NULL, &flags,
                                              NULL, NULL, &rs_ctx);
    TEST_ASSERT(ret == result || ret == MBEDTLS_ERR_ECP_IN_PROGRESS);

exit:
    mbedtls_x509_crt_restart_free(&rs_ctx);
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&ca);
    MD_OR_USE_PSA_DONE();
}

static void test_x509_verify_restart_wrapper( void ** params )
{

    test_x509_verify_restart( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint );
}
#endif /* MBEDTLS_ECDSA_C */
#endif /* MBEDTLS_ECP_RESTARTABLE */
#endif /* MBEDTLS_X509_CRL_PARSE_C */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_X509_CRL_PARSE_C)
#line 710 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_verify(char *crt_file, char *ca_file, char *crl_file,
                 char *cn_name_str, int result, int flags_result,
                 char *profile_str,
                 char *verify_callback)
{
    mbedtls_x509_crt   crt;
    mbedtls_x509_crt   ca;
    mbedtls_x509_crl    crl;
    uint32_t         flags = 0;
    int         res;
    int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *) = NULL;
    char *cn_name = NULL;
    const mbedtls_x509_crt_profile *profile;

    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crl_init(&crl);
    MD_OR_USE_PSA_INIT();

    if (strcmp(cn_name_str, "NULL") != 0) {
        cn_name = cn_name_str;
    }

    if (strcmp(profile_str, "") == 0) {
        profile = &mbedtls_x509_crt_profile_default;
    } else if (strcmp(profile_str, "next") == 0) {
        profile = &mbedtls_x509_crt_profile_next;
    } else if (strcmp(profile_str, "suite_b") == 0) {
        profile = &mbedtls_x509_crt_profile_suiteb;
    } else if (strcmp(profile_str, "compat") == 0) {
        profile = &compat_profile;
    } else if (strcmp(profile_str, "all") == 0) {
        profile = &profile_all;
    } else {
        TEST_FAIL("Unknown algorithm profile");
    }

    if (strcmp(verify_callback, "NULL") == 0) {
        f_vrfy = NULL;
    } else if (strcmp(verify_callback, "verify_none") == 0) {
        f_vrfy = verify_none;
    } else if (strcmp(verify_callback, "verify_all") == 0) {
        f_vrfy = verify_all;
    } else {
        TEST_FAIL("No known verify callback selected");
    }

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    TEST_EQUAL(mbedtls_x509_crt_parse_file(&ca, ca_file), 0);
    TEST_EQUAL(mbedtls_x509_crl_parse_file(&crl, crl_file), 0);

    res = mbedtls_x509_crt_verify_with_profile(&crt,
                                               &ca,
                                               &crl,
                                               profile,
                                               cn_name,
                                               &flags,
                                               f_vrfy,
                                               NULL);

    TEST_EQUAL(res, result);
    TEST_EQUAL(flags, (uint32_t) flags_result);

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    /* CRLs aren't supported with CA callbacks, so skip the CA callback
     * version of the test if CRLs are in use. */
    if (strcmp(crl_file, "") == 0) {
        flags = 0;

        res = mbedtls_x509_crt_verify_with_ca_cb(&crt,
                                                 ca_callback,
                                                 &ca,
                                                 profile,
                                                 cn_name,
                                                 &flags,
                                                 f_vrfy,
                                                 NULL);

        TEST_EQUAL(res, result);
        TEST_EQUAL(flags, (uint32_t) (flags_result));
    }
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
exit:
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&ca);
    mbedtls_x509_crl_free(&crl);
    MD_OR_USE_PSA_DONE();
}

static void test_x509_verify_wrapper( void ** params )
{

    test_x509_verify( (char *) params[0], (char *) params[1], (char *) params[2], (char *) params[3], ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, (char *) params[6], (char *) params[7] );
}
#endif /* MBEDTLS_X509_CRL_PARSE_C */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_X509_CRL_PARSE_C)
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
#line 801 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_verify_ca_cb_failure(char *crt_file, char *ca_file, char *name,
                               int exp_ret)
{
    int ret;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt ca;
    uint32_t flags = 0;

    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&ca);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    TEST_EQUAL(mbedtls_x509_crt_parse_file(&ca, ca_file), 0);

    if (strcmp(name, "NULL") == 0) {
        name = NULL;
    }

    ret = mbedtls_x509_crt_verify_with_ca_cb(&crt, ca_callback_fail, &ca,
                                             &compat_profile, name, &flags,
                                             NULL, NULL);

    TEST_EQUAL(ret, exp_ret);
    TEST_EQUAL(flags, (uint32_t) (-1));
exit:
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&ca);
    USE_PSA_DONE();
}

static void test_x509_verify_ca_cb_failure_wrapper( void ** params )
{

    test_x509_verify_ca_cb_failure( (char *) params[0], (char *) params[1], (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
#endif /* MBEDTLS_X509_CRL_PARSE_C */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 834 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_verify_callback(char *crt_file, char *ca_file, char *name,
                          int exp_ret, char *exp_vrfy_out)
{
    int ret;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt ca;
    uint32_t flags = 0;
    verify_print_context vrfy_ctx;

    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&ca);
    MD_OR_USE_PSA_INIT();

    verify_print_init(&vrfy_ctx);

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    TEST_EQUAL(mbedtls_x509_crt_parse_file(&ca, ca_file), 0);

    if (strcmp(name, "NULL") == 0) {
        name = NULL;
    }

    ret = mbedtls_x509_crt_verify_with_profile(&crt, &ca, NULL,
                                               &compat_profile,
                                               name, &flags,
                                               verify_print, &vrfy_ctx);

    TEST_EQUAL(ret, exp_ret);
    TEST_EQUAL(strcmp(vrfy_ctx.buf, exp_vrfy_out), 0);

exit:
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&ca);
    MD_OR_USE_PSA_DONE();
}

static void test_x509_verify_callback_wrapper( void ** params )
{

    test_x509_verify_callback( (char *) params[0], (char *) params[1], (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint, (char *) params[4] );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 872 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_dn_gets_subject_replace(char *crt_file,
                                          char *new_subject_ou,
                                          char *result_str,
                                          int ret)
{
    mbedtls_x509_crt   crt;
    char buf[2000];
    int res = 0;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    memset(buf, 0, 2000);

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    crt.subject.next->val.p = (unsigned char *) new_subject_ou;
    crt.subject.next->val.len = strlen(new_subject_ou);

    res =  mbedtls_x509_dn_gets(buf, 2000, &crt.subject);

    if (ret != 0) {
        TEST_EQUAL(res, ret);
    } else {
        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);
        TEST_EQUAL(strcmp(buf, result_str), 0);
    }
exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_dn_gets_subject_replace_wrapper( void ** params )
{

    test_mbedtls_x509_dn_gets_subject_replace( (char *) params[0], (char *) params[1], (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 906 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_dn_gets(char *crt_file, char *entity, char *result_str)
{
    mbedtls_x509_crt   crt;
    char buf[2000];
    int res = 0;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    memset(buf, 0, 2000);

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    if (strcmp(entity, "subject") == 0) {
        res =  mbedtls_x509_dn_gets(buf, 2000, &crt.subject);
    } else if (strcmp(entity, "issuer") == 0) {
        res =  mbedtls_x509_dn_gets(buf, 2000, &crt.issuer);
    } else {
        TEST_FAIL("Unknown entity");
    }

    TEST_ASSERT(res != -1);
    TEST_ASSERT(res != -2);

    TEST_EQUAL(strcmp(buf, result_str), 0);

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_dn_gets_wrapper( void ** params )
{

    test_mbedtls_x509_dn_gets( (char *) params[0], (char *) params[1], (char *) params[2] );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 938 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_get_name(char *rdn_sequence, int exp_ret)
{
    unsigned char *name = NULL;
    unsigned char *p;
    size_t name_len;
    mbedtls_x509_name head;
    int ret;

    USE_PSA_INIT();
    memset(&head, 0, sizeof(head));

    name = mbedtls_test_unhexify_alloc(rdn_sequence, &name_len);
    p = name;

    ret = mbedtls_x509_get_name(&p, (name + name_len), &head);
    if (ret == 0) {
        mbedtls_asn1_free_named_data_list_shallow(head.next);
    }

    TEST_EQUAL(ret, exp_ret);

exit:
    mbedtls_free(name);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_get_name_wrapper( void ** params )
{

    test_mbedtls_x509_get_name( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CREATE_C)
#if defined(MBEDTLS_X509_USE_C)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 966 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_dn_get_next(char *name_str,
                              int next_merged,
                              char *expected_oids,
                              int exp_count,
                              char *exp_dn_gets)
{
    int ret = 0, i;
    size_t len = 0, out_size;
    mbedtls_asn1_named_data *names = NULL;
    mbedtls_x509_name parsed;
    memset(&parsed, 0, sizeof(parsed));
    mbedtls_x509_name *parsed_cur;
    // Size of buf is maximum required for test cases
    unsigned char buf[80] = { 0 };
    unsigned char *out = NULL;
    unsigned char *c = buf + sizeof(buf);
    const char *short_name;

    USE_PSA_INIT();

    // Additional size required for trailing space
    out_size = strlen(expected_oids) + 2;
    TEST_CALLOC(out, out_size);

    TEST_EQUAL(mbedtls_x509_string_to_names(&names, name_str), 0);

    ret = mbedtls_x509_write_names(&c, buf, names);
    TEST_LE_S(0, ret);

    TEST_EQUAL(mbedtls_asn1_get_tag(&c, buf + sizeof(buf), &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), 0);
    TEST_EQUAL(mbedtls_x509_get_name(&c, buf + sizeof(buf), &parsed), 0);

    // Iterate over names and set next_merged nodes
    parsed_cur = &parsed;
    for (; next_merged != 0 && parsed_cur != NULL; next_merged = next_merged >> 1) {
        parsed_cur->next_merged = next_merged & 0x01;
        parsed_cur = parsed_cur->next;
    }

    // Iterate over RDN nodes and print OID of first element to buffer
    parsed_cur = &parsed;
    len = 0;
    for (i = 0; parsed_cur != NULL; i++) {
        TEST_EQUAL(mbedtls_oid_get_attr_short_name(&parsed_cur->oid,
                                                   &short_name), 0);
        len += mbedtls_snprintf((char *) out + len, out_size - len, "%s ", short_name);
        parsed_cur = mbedtls_x509_dn_get_next(parsed_cur);
    }
    out[len-1] = 0;

    TEST_EQUAL(exp_count, i);
    TEST_EQUAL(strcmp((char *) out, expected_oids), 0);
    mbedtls_free(out);
    out = NULL;

    out_size = strlen(exp_dn_gets) + 1;
    TEST_CALLOC(out, out_size);

    TEST_LE_S(0, mbedtls_x509_dn_gets((char *) out, out_size, &parsed));
    TEST_EQUAL(strcmp((char *) out, exp_dn_gets), 0);
exit:
    mbedtls_free(out);
    mbedtls_asn1_free_named_data_list(&names);
    mbedtls_asn1_free_named_data_list_shallow(parsed.next);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_dn_get_next_wrapper( void ** params )
{

    test_mbedtls_x509_dn_get_next( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint, (char *) params[4] );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_X509_USE_C */
#endif /* MBEDTLS_X509_CREATE_C */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1036 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_time_is_past(char *crt_file, char *entity, int result)
{
    mbedtls_x509_crt   crt;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);

    if (strcmp(entity, "valid_from") == 0) {
        TEST_EQUAL(mbedtls_x509_time_is_past(&crt.valid_from), result);
    } else if (strcmp(entity, "valid_to") == 0) {
        TEST_EQUAL(mbedtls_x509_time_is_past(&crt.valid_to), result);
    } else {
        TEST_FAIL("Unknown entity");
    }

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_time_is_past_wrapper( void ** params )
{

    test_mbedtls_x509_time_is_past( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1060 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_time_is_future(char *crt_file, char *entity, int result)
{
    mbedtls_x509_crt   crt;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);

    if (strcmp(entity, "valid_from") == 0) {
        TEST_EQUAL(mbedtls_x509_time_is_future(&crt.valid_from), result);
    } else if (strcmp(entity, "valid_to") == 0) {
        TEST_EQUAL(mbedtls_x509_time_is_future(&crt.valid_to), result);
    } else {
        TEST_FAIL("Unknown entity");
    }

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_time_is_future_wrapper( void ** params )
{

    test_mbedtls_x509_time_is_future( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#line 1084 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509parse_crt_file(char *crt_file, int result)
{
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), result);

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509parse_crt_file_wrapper( void ** params )
{

    test_x509parse_crt_file( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#line 1100 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_get_ca_istrue(char *crt_file, int result)
{
    mbedtls_x509_crt   crt;
    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);
    TEST_EQUAL(mbedtls_x509_crt_get_ca_istrue(&crt), result);
exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_get_ca_istrue_wrapper( void ** params )
{

    test_mbedtls_x509_get_ca_istrue( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1115 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509parse_crt(data_t *buf, char *result_str, int result)
{
    mbedtls_x509_crt   crt;
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    unsigned char output[2000] = { 0 };
    int res;
#else
    ((void) result_str);
#endif

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_der(&crt, buf->x, buf->len), result);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if ((result) == 0) {
        res = mbedtls_x509_crt_info((char *) output, 2000, "", &crt);
        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);

        TEST_EQUAL(strcmp((char *) output, result_str), 0);
    }
    memset(output, 0, 2000);
#endif

    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_init(&crt);

    TEST_EQUAL(mbedtls_x509_crt_parse_der_nocopy(&crt, buf->x, buf->len), result);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if ((result) == 0) {
        memset(output, 0, 2000);

        res = mbedtls_x509_crt_info((char *) output, 2000, "", &crt);

        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);

        TEST_EQUAL(strcmp((char *) output, result_str), 0);
    }
    memset(output, 0, 2000);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_init(&crt);

    TEST_EQUAL(mbedtls_x509_crt_parse_der_with_ext_cb(&crt, buf->x, buf->len, 0, NULL, NULL),
               result);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if ((result) == 0) {
        res = mbedtls_x509_crt_info((char *) output, 2000, "", &crt);

        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);

        TEST_EQUAL(strcmp((char *) output, result_str), 0);
    }
    memset(output, 0, 2000);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_init(&crt);

    TEST_EQUAL(mbedtls_x509_crt_parse_der_with_ext_cb(&crt, buf->x, buf->len, 1, NULL, NULL),
               result);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if ((result) == 0) {
        res = mbedtls_x509_crt_info((char *) output, 2000, "", &crt);

        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);

        TEST_EQUAL(strcmp((char *) output, result_str), 0);
    }
#endif /* !MBEDTLS_X509_REMOVE_INFO */

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509parse_crt_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_x509parse_crt( &data0, (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1198 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509parse_crt_cb(data_t *buf, char *result_str, int result)
{
    mbedtls_x509_crt   crt;
    mbedtls_x509_buf   oid;

#if !defined(MBEDTLS_X509_REMOVE_INFO)
    unsigned char output[2000] = { 0 };
    int res;
#else
    ((void) result_str);
#endif

    oid.tag = MBEDTLS_ASN1_OID;
    oid.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_PKIX "\x01\x1F");
    oid.p = (unsigned char *) MBEDTLS_OID_PKIX "\x01\x1F";

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_der_with_ext_cb(&crt, buf->x, buf->len, 0, parse_crt_ext_cb,
                                                      &oid), result);
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if ((result) == 0) {
        res = mbedtls_x509_crt_info((char *) output, 2000, "", &crt);

        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);

        TEST_EQUAL(strcmp((char *) output, result_str), 0);
    }
    memset(output, 0, 2000);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_init(&crt);

    TEST_EQUAL(mbedtls_x509_crt_parse_der_with_ext_cb(&crt, buf->x, buf->len, 1, parse_crt_ext_cb,
                                                      &oid), (result));
#if !defined(MBEDTLS_X509_REMOVE_INFO)
    if ((result) == 0) {
        res = mbedtls_x509_crt_info((char *) output, 2000, "", &crt);

        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);

        TEST_EQUAL(strcmp((char *) output, result_str), 0);
    }
#endif /* !MBEDTLS_X509_REMOVE_INFO */

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509parse_crt_cb_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_x509parse_crt_cb( &data0, (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CRL_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 1254 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509parse_crl(data_t *buf, char *result_str, int result)
{
    mbedtls_x509_crl   crl;
    unsigned char output[2000];
    int res;

    mbedtls_x509_crl_init(&crl);
    USE_PSA_INIT();

    memset(output, 0, 2000);


    TEST_EQUAL(mbedtls_x509_crl_parse(&crl, buf->x, buf->len), (result));
    if ((result) == 0) {
        res = mbedtls_x509_crl_info((char *) output, 2000, "", &crl);

        TEST_ASSERT(res != -1);
        TEST_ASSERT(res != -2);

        TEST_EQUAL(strcmp((char *) output, result_str), 0);
    }

exit:
    mbedtls_x509_crl_free(&crl);
    USE_PSA_DONE();
}

static void test_x509parse_crl_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_x509parse_crl( &data0, (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRL_PARSE_C */
#if defined(MBEDTLS_X509_CSR_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 1283 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_csr_parse(data_t *csr_der, char *ref_out, int ref_ret)
{
    mbedtls_x509_csr csr;
    char my_out[1000];
    int my_ret;

    mbedtls_x509_csr_init(&csr);
    USE_PSA_INIT();

    memset(my_out, 0, sizeof(my_out));

    my_ret = mbedtls_x509_csr_parse_der(&csr, csr_der->x, csr_der->len);
    TEST_EQUAL(my_ret, ref_ret);

    if (ref_ret == 0) {
        size_t my_out_len = mbedtls_x509_csr_info(my_out, sizeof(my_out), "", &csr);
        TEST_EQUAL(my_out_len, strlen(ref_out));
        TEST_EQUAL(strcmp(my_out, ref_out), 0);
    }

exit:
    mbedtls_x509_csr_free(&csr);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_csr_parse_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_mbedtls_x509_csr_parse( &data0, (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CSR_PARSE_C */
#if defined(MBEDTLS_X509_CSR_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 1310 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_csr_parse_with_ext_cb(data_t *csr_der, char *ref_out, int ref_ret, int accept)
{
    mbedtls_x509_csr csr;
    char my_out[1000];
    int my_ret;

    mbedtls_x509_csr_init(&csr);
    USE_PSA_INIT();

    memset(my_out, 0, sizeof(my_out));

    my_ret = mbedtls_x509_csr_parse_der_with_ext_cb(&csr, csr_der->x, csr_der->len,
                                                    accept ? parse_csr_ext_accept_cb :
                                                    parse_csr_ext_reject_cb,
                                                    NULL);
    TEST_EQUAL(my_ret, ref_ret);

    if (ref_ret == 0) {
        size_t my_out_len = mbedtls_x509_csr_info(my_out, sizeof(my_out), "", &csr);
        TEST_EQUAL(my_out_len, strlen(ref_out));
        TEST_EQUAL(strcmp(my_out, ref_out), 0);
    }

exit:
    mbedtls_x509_csr_free(&csr);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_csr_parse_with_ext_cb_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_mbedtls_x509_csr_parse_with_ext_cb( &data0, (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CSR_PARSE_C */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CSR_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 1340 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_csr_parse_file(char *csr_file, char *ref_out, int ref_ret)
{
    mbedtls_x509_csr csr;
    char my_out[1000];
    int my_ret;

    mbedtls_x509_csr_init(&csr);
    USE_PSA_INIT();

    memset(my_out, 0, sizeof(my_out));

    my_ret = mbedtls_x509_csr_parse_file(&csr, csr_file);
    TEST_EQUAL(my_ret, ref_ret);

    if (ref_ret == 0) {
        size_t my_out_len = mbedtls_x509_csr_info(my_out, sizeof(my_out), "", &csr);
        TEST_EQUAL(my_out_len, strlen(ref_out));
        TEST_EQUAL(strcmp(my_out, ref_out), 0);
    }

exit:
    mbedtls_x509_csr_free(&csr);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_csr_parse_file_wrapper( void ** params )
{

    test_mbedtls_x509_csr_parse_file( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CSR_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1367 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_crt_parse_file(char *crt_path, int ret, int nb_crt)
{
    mbedtls_x509_crt chain, *cur;
    int i;

    mbedtls_x509_crt_init(&chain);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&chain, crt_path), ret);

    /* Check how many certs we got */
    for (i = 0, cur = &chain; cur != NULL; cur = cur->next) {
        if (cur->raw.p != NULL) {
            i++;
        }
    }

    TEST_EQUAL(i, nb_crt);

exit:
    mbedtls_x509_crt_free(&chain);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_crt_parse_file_wrapper( void ** params )
{

    test_mbedtls_x509_crt_parse_file( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1393 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_crt_parse_path(char *crt_path, int ret, int nb_crt)
{
    mbedtls_x509_crt chain, *cur;
    int i;

    mbedtls_x509_crt_init(&chain);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_path(&chain, crt_path), ret);

    /* Check how many certs we got */
    for (i = 0, cur = &chain; cur != NULL; cur = cur->next) {
        if (cur->raw.p != NULL) {
            i++;
        }
    }

    TEST_EQUAL(i, nb_crt);

exit:
    mbedtls_x509_crt_free(&chain);
    USE_PSA_DONE();
}

static void test_mbedtls_x509_crt_parse_path_wrapper( void ** params )
{

    test_mbedtls_x509_crt_parse_path( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1419 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_crt_verify_max(char *ca_file, char *chain_dir, int nb_int,
                                 int ret_chk, int flags_chk)
{
    char file_buf[128];
    int ret;
    uint32_t flags;
    mbedtls_x509_crt trusted, chain;

    /*
     * We expect chain_dir to contain certificates 00.crt, 01.crt, etc.
     * with NN.crt signed by NN-1.crt
     */
    mbedtls_x509_crt_init(&trusted);
    mbedtls_x509_crt_init(&chain);
    MD_OR_USE_PSA_INIT();

    /* Load trusted root */
    TEST_EQUAL(mbedtls_x509_crt_parse_file(&trusted, ca_file), 0);

    /* Load a chain with nb_int intermediates (from 01 to nb_int),
     * plus one "end-entity" cert (nb_int + 1) */
    ret = mbedtls_snprintf(file_buf, sizeof(file_buf), "%s/c%02d.pem", chain_dir,
                           nb_int + 1);
    TEST_ASSERT(ret > 0 && (size_t) ret < sizeof(file_buf));
    TEST_EQUAL(mbedtls_x509_crt_parse_file(&chain, file_buf), 0);

    /* Try to verify that chain */
    ret = mbedtls_x509_crt_verify(&chain, &trusted, NULL, NULL, &flags,
                                  NULL, NULL);
    TEST_EQUAL(ret, ret_chk);
    TEST_EQUAL(flags, (uint32_t) flags_chk);

exit:
    mbedtls_x509_crt_free(&chain);
    mbedtls_x509_crt_free(&trusted);
    MD_OR_USE_PSA_DONE();
}

static void test_mbedtls_x509_crt_verify_max_wrapper( void ** params )
{

    test_mbedtls_x509_crt_verify_max( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1459 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_mbedtls_x509_crt_verify_chain(char *chain_paths, char *trusted_ca,
                                   int flags_result, int result,
                                   char *profile_name, int vrfy_fatal_lvls)
{
    char *act;
    uint32_t flags;
    int res;
    mbedtls_x509_crt trusted, chain;
    const mbedtls_x509_crt_profile *profile = NULL;

    mbedtls_x509_crt_init(&chain);
    mbedtls_x509_crt_init(&trusted);
    MD_OR_USE_PSA_INIT();

    while ((act = mystrsep(&chain_paths, " ")) != NULL) {
        TEST_EQUAL(mbedtls_x509_crt_parse_file(&chain, act), 0);
    }
    TEST_EQUAL(mbedtls_x509_crt_parse_file(&trusted, trusted_ca), 0);

    if (strcmp(profile_name, "") == 0) {
        profile = &mbedtls_x509_crt_profile_default;
    } else if (strcmp(profile_name, "next") == 0) {
        profile = &mbedtls_x509_crt_profile_next;
    } else if (strcmp(profile_name, "suiteb") == 0) {
        profile = &mbedtls_x509_crt_profile_suiteb;
    } else if (strcmp(profile_name, "rsa3072") == 0) {
        profile = &profile_rsa3072;
    } else if (strcmp(profile_name, "sha512") == 0) {
        profile = &profile_sha512;
    }

    res = mbedtls_x509_crt_verify_with_profile(&chain, &trusted, NULL, profile,
                                               NULL, &flags, verify_fatal, &vrfy_fatal_lvls);

    TEST_EQUAL(res, (result));
    TEST_EQUAL(flags, (uint32_t) (flags_result));

exit:
    mbedtls_x509_crt_free(&trusted);
    mbedtls_x509_crt_free(&chain);
    MD_OR_USE_PSA_DONE();
}

static void test_mbedtls_x509_crt_verify_chain_wrapper( void ** params )
{

    test_mbedtls_x509_crt_verify_chain( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, (char *) params[4], ((mbedtls_test_argument_t *) params[5])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_X509_USE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#line 1504 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_oid_desc(data_t *buf, char *ref_desc)
{
    mbedtls_x509_buf oid;
    const char *desc = NULL;
    int ret;

    USE_PSA_INIT();

    oid.tag = MBEDTLS_ASN1_OID;
    oid.p   = buf->x;
    oid.len   = buf->len;

    ret = mbedtls_oid_get_extended_key_usage(&oid, &desc);

    if (strcmp(ref_desc, "notfound") == 0) {
        TEST_ASSERT(ret != 0);
        TEST_ASSERT(desc == NULL);
    } else {
        TEST_EQUAL(ret, 0);
        TEST_ASSERT(desc != NULL);
        TEST_EQUAL(strcmp(desc, ref_desc), 0);
    }

exit:
    USE_PSA_DONE();
}

static void test_x509_oid_desc_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_x509_oid_desc( &data0, (char *) params[2] );
}
#endif /* !MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_USE_C */
#if defined(MBEDTLS_X509_USE_C)
#line 1533 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_oid_numstr(data_t *oid_buf, char *numstr, int blen, int ret)
{
    mbedtls_x509_buf oid;
    char num_buf[100];

    USE_PSA_INIT();

    memset(num_buf, 0x2a, sizeof(num_buf));

    oid.tag = MBEDTLS_ASN1_OID;
    oid.p   = oid_buf->x;
    oid.len   = oid_buf->len;

    TEST_ASSERT((size_t) blen <= sizeof(num_buf));

    TEST_EQUAL(mbedtls_oid_get_numeric_string(num_buf, blen, &oid), ret);

    if (ret >= 0) {
        TEST_EQUAL(num_buf[ret], 0);
        TEST_EQUAL(strcmp(num_buf, numstr), 0);
    }

exit:
    USE_PSA_DONE();
}

static void test_x509_oid_numstr_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_x509_oid_numstr( &data0, (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_X509_USE_C */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1561 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_check_key_usage(char *crt_file, int usage, int ret)
{
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);

    TEST_EQUAL(mbedtls_x509_crt_check_key_usage(&crt, usage), ret);

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509_check_key_usage_wrapper( void ** params )
{

    test_x509_check_key_usage( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#line 1579 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_check_extended_key_usage(char *crt_file, data_t *oid, int ret
                                   )
{
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init(&crt);
    USE_PSA_INIT();

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, crt_file), 0);

    TEST_EQUAL(mbedtls_x509_crt_check_extended_key_usage(&crt, (const char *) oid->x, oid->len),
               ret);

exit:
    mbedtls_x509_crt_free(&crt);
    USE_PSA_DONE();
}

static void test_x509_check_extended_key_usage_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_x509_check_extended_key_usage( (char *) params[0], &data1, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */
#if defined(MBEDTLS_X509_USE_C)
#line 1599 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_get_time(int tag, char *time_str, int ret, int year, int mon,
                   int day, int hour, int min, int sec)
{
    mbedtls_x509_time time;
    unsigned char buf[21];
    unsigned char *start = buf;
    unsigned char *end = buf;

    USE_PSA_INIT();
    memset(&time, 0x00, sizeof(time));
    *end = (unsigned char) tag; end++;
    *end = strlen(time_str);
    TEST_ASSERT(*end < 20);
    end++;
    memcpy(end, time_str, (size_t) *(end - 1));
    end += *(end - 1);

    TEST_EQUAL(mbedtls_x509_get_time(&start, end, &time), ret);
    if (ret == 0) {
        TEST_EQUAL(year, time.year);
        TEST_EQUAL(mon, time.mon);
        TEST_EQUAL(day, time.day);
        TEST_EQUAL(hour, time.hour);
        TEST_EQUAL(min, time.min);
        TEST_EQUAL(sec, time.sec);
    }
exit:
    USE_PSA_DONE();
}

static void test_x509_get_time_wrapper( void ** params )
{

    test_x509_get_time( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint );
}
#endif /* MBEDTLS_X509_USE_C */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
#line 1631 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_parse_rsassa_pss_params(data_t *params, int params_tag,
                                  int ref_msg_md, int ref_mgf_md,
                                  int ref_salt_len, int ref_ret)
{
    int my_ret;
    mbedtls_x509_buf buf;
    mbedtls_md_type_t my_msg_md, my_mgf_md;
    int my_salt_len;

    USE_PSA_INIT();

    buf.p = params->x;
    buf.len = params->len;
    buf.tag = params_tag;

    my_ret = mbedtls_x509_get_rsassa_pss_params(&buf, &my_msg_md, &my_mgf_md,
                                                &my_salt_len);

    TEST_EQUAL(my_ret, ref_ret);

    if (ref_ret == 0) {
        TEST_EQUAL(my_msg_md, (mbedtls_md_type_t) ref_msg_md);
        TEST_EQUAL(my_mgf_md, (mbedtls_md_type_t) ref_mgf_md);
        TEST_EQUAL(my_salt_len, ref_salt_len);
    }

exit:
    USE_PSA_DONE();
}

static void test_x509_parse_rsassa_pss_params_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_x509_parse_rsassa_pss_params( &data0, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint );
}
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#line 1663 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_crt_parse_subjectkeyid(char *file, data_t *subjectKeyId, int ref_ret)
{
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init(&crt);

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, file), ref_ret);

    if (ref_ret == 0) {
        TEST_EQUAL(crt.subject_key_id.tag, MBEDTLS_ASN1_OCTET_STRING);
        TEST_EQUAL(memcmp(crt.subject_key_id.p, subjectKeyId->x, subjectKeyId->len), 0);
        TEST_EQUAL(crt.subject_key_id.len, subjectKeyId->len);
    } else {
        TEST_EQUAL(crt.subject_key_id.tag, 0);
        TEST_EQUAL(crt.subject_key_id.len, 0);
    }

exit:
    mbedtls_x509_crt_free(&crt);
}

static void test_x509_crt_parse_subjectkeyid_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_x509_crt_parse_subjectkeyid( (char *) params[0], &data1, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#line 1686 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_x509parse.function"
static void test_x509_crt_parse_authoritykeyid(char *file,
                                   data_t *keyId,
                                   char *authorityKeyId_issuer,
                                   data_t *serial,
                                   int ref_ret)
{
    mbedtls_x509_crt crt;
    mbedtls_x509_subject_alternative_name san;
    char name_buf[128];

    mbedtls_x509_crt_init(&crt);

    TEST_EQUAL(mbedtls_x509_crt_parse_file(&crt, file), ref_ret);

    if (ref_ret == 0) {
        /* KeyId test */
        if (keyId->len > 0) {
            TEST_EQUAL(crt.authority_key_id.keyIdentifier.tag, MBEDTLS_ASN1_OCTET_STRING);
            TEST_EQUAL(memcmp(crt.authority_key_id.keyIdentifier.p, keyId->x, keyId->len), 0);
            TEST_EQUAL(crt.authority_key_id.keyIdentifier.len, keyId->len);
        } else {
            TEST_EQUAL(crt.authority_key_id.keyIdentifier.tag, 0);
            TEST_EQUAL(crt.authority_key_id.keyIdentifier.len, 0);
        }


        /* Issuer test */
        if (strlen(authorityKeyId_issuer) > 0) {
            mbedtls_x509_sequence *issuerPtr = &crt.authority_key_id.authorityCertIssuer;

            TEST_EQUAL(mbedtls_x509_parse_subject_alt_name(&issuerPtr->buf, &san), 0);

            TEST_ASSERT(mbedtls_x509_dn_gets(name_buf, sizeof(name_buf),
                                             &san.san.directory_name)
                        > 0);
            TEST_EQUAL(strcmp(name_buf, authorityKeyId_issuer), 0);

            mbedtls_x509_free_subject_alt_name(&san);
        }

        /* Serial test */
        if (serial->len > 0) {
            TEST_EQUAL(crt.authority_key_id.authorityCertSerialNumber.tag,
                       MBEDTLS_ASN1_INTEGER);
            TEST_EQUAL(memcmp(crt.authority_key_id.authorityCertSerialNumber.p,
                              serial->x, serial->len), 0);
            TEST_EQUAL(crt.authority_key_id.authorityCertSerialNumber.len, serial->len);
        } else {
            TEST_EQUAL(crt.authority_key_id.authorityCertSerialNumber.tag, 0);
            TEST_EQUAL(crt.authority_key_id.authorityCertSerialNumber.len, 0);
        }

    } else {
        TEST_EQUAL(crt.authority_key_id.keyIdentifier.tag, 0);
        TEST_EQUAL(crt.authority_key_id.keyIdentifier.len, 0);

        TEST_EQUAL(crt.authority_key_id.authorityCertSerialNumber.tag, 0);
        TEST_EQUAL(crt.authority_key_id.authorityCertSerialNumber.len, 0);
    }

exit:
    mbedtls_x509_crt_free(&crt);
}

static void test_x509_crt_parse_authoritykeyid_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};

    test_x509_crt_parse_authoritykeyid( (char *) params[0], &data1, (char *) params[3], &data4, ((mbedtls_test_argument_t *) params[6])->sint );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */


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
    
        case 0:
            {
                *out_value = MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_X509_BADCERT_MISSING;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCRL_EXPIRED;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_X509_BADCERT_OTHER | 0x80000000;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 10:
            {
                *out_value = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            }
            break;
        case 11:
            {
                *out_value = MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_EXPIRED;
            }
            break;
        case 12:
            {
                *out_value = MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_FUTURE;
            }
            break;
        case 13:
            {
                *out_value = MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_EXPIRED | MBEDTLS_X509_BADCERT_CN_MISMATCH;
            }
            break;
        case 14:
            {
                *out_value = MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_FUTURE | MBEDTLS_X509_BADCERT_CN_MISMATCH;
            }
            break;
        case 15:
            {
                *out_value = MBEDTLS_X509_BADCRL_EXPIRED;
            }
            break;
        case 16:
            {
                *out_value = MBEDTLS_X509_BADCRL_FUTURE;
            }
            break;
        case 17:
            {
                *out_value = MBEDTLS_X509_BADCERT_REVOKED;
            }
            break;
        case 18:
            {
                *out_value = MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH;
            }
            break;
        case 19:
            {
                *out_value = MBEDTLS_X509_BADCERT_EXPIRED;
            }
            break;
        case 20:
            {
                *out_value = MBEDTLS_X509_BADCERT_FUTURE;
            }
            break;
        case 21:
            {
                *out_value = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            }
            break;
        case 22:
            {
                *out_value = MBEDTLS_X509_BADCERT_BAD_MD;
            }
            break;
        case 23:
            {
                *out_value = MBEDTLS_X509_BADCRL_BAD_MD | MBEDTLS_X509_BADCERT_BAD_MD;
            }
            break;
        case 24:
            {
                *out_value = MBEDTLS_X509_BADCERT_OTHER;
            }
            break;
        case 25:
            {
                *out_value = MBEDTLS_X509_BADCERT_CN_MISMATCH;
            }
            break;
        case 26:
            {
                *out_value = MBEDTLS_X509_BADCERT_CN_MISMATCH + MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            }
            break;
        case 27:
            {
                *out_value = MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            }
            break;
        case 28:
            {
                *out_value = MBEDTLS_X509_BADCERT_REVOKED|MBEDTLS_X509_BADCRL_FUTURE;
            }
            break;
        case 29:
            {
                *out_value = MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY|MBEDTLS_X509_BADCRL_BAD_MD|MBEDTLS_X509_BADCRL_BAD_PK;
            }
            break;
        case 30:
            {
                *out_value = MBEDTLS_X509_BADCERT_BAD_PK;
            }
            break;
        case 31:
            {
                *out_value = MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCRL_BAD_MD;
            }
            break;
        case 32:
            {
                *out_value = MBEDTLS_ERR_X509_FATAL_ERROR;
            }
            break;
        case 33:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_FORMAT;
            }
            break;
        case 34:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 35:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 36:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 37:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_SERIAL + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 38:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 39:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 40:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 41:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 42:
            {
                *out_value = MBEDTLS_ERR_X509_UNKNOWN_VERSION;
            }
            break;
        case 43:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_SERIAL + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 44:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_SERIAL + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 45:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 46:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 47:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 48:
            {
                *out_value = MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND;
            }
            break;
        case 49:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 50:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_ALG;
            }
            break;
        case 51:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 52:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;;
            }
            break;
        case 53:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 54:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 55:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 56:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 57:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_DATE;
            }
            break;
        case 58:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 59:
            {
                *out_value = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 60:
            {
                *out_value = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 61:
            {
                *out_value = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 62:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 63:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 64:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_ALG + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 65:
            {
                *out_value = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
            }
            break;
        case 66:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 67:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 68:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 69:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_INVALID_DATA;
            }
            break;
        case 70:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_PUBKEY;
            }
            break;
        case 71:
            {
                *out_value = MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 72:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 73:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 74:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 75:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 76:
            {
                *out_value = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
            }
            break;
        case 77:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            }
            break;
        case 78:
            {
                *out_value = MBEDTLS_ERR_X509_SIG_MISMATCH;
            }
            break;
        case 79:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 80:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 81:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
        case 82:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_INVALID_DATA;
            }
            break;
        case 83:
            {
                *out_value = MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG;
            }
            break;
        case 84:
            {
                *out_value = MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 85:
            {
                *out_value = MBEDTLS_X509_MAX_INTERMEDIATE_CA;
            }
            break;
        case 86:
            {
                *out_value = MBEDTLS_X509_MAX_INTERMEDIATE_CA-1;
            }
            break;
        case 87:
            {
                *out_value = MBEDTLS_X509_MAX_INTERMEDIATE_CA+1;
            }
            break;
        case 88:
            {
                *out_value = MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY;
            }
            break;
        case 89:
            {
                *out_value = MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY;
            }
            break;
        case 90:
            {
                *out_value = MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_KEY;
            }
            break;
        case 91:
            {
                *out_value = MBEDTLS_ERR_OID_BUF_TOO_SMALL;
            }
            break;
        case 92:
            {
                *out_value = MBEDTLS_ERR_ASN1_INVALID_DATA;
            }
            break;
        case 93:
            {
                *out_value = MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
            }
            break;
        case 94:
            {
                *out_value = MBEDTLS_X509_KU_KEY_CERT_SIGN;
            }
            break;
        case 95:
            {
                *out_value = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
            }
            break;
        case 96:
            {
                *out_value = MBEDTLS_X509_KU_KEY_CERT_SIGN|MBEDTLS_X509_KU_CRL_SIGN;
            }
            break;
        case 97:
            {
                *out_value = MBEDTLS_X509_KU_KEY_ENCIPHERMENT|MBEDTLS_X509_KU_KEY_AGREEMENT;
            }
            break;
        case 98:
            {
                *out_value = MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_KEY_ENCIPHERMENT|MBEDTLS_X509_KU_DECIPHER_ONLY;
            }
            break;
        case 99:
            {
                *out_value = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
            }
            break;
        case 100:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 101:
            {
                *out_value = MBEDTLS_ASN1_SEQUENCE;
            }
            break;
        case 102:
            {
                *out_value = MBEDTLS_MD_SHA256;
            }
            break;
        case 103:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_INVALID_DATA;
            }
            break;
        case 104:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_OID_NOT_FOUND;
            }
            break;
        case 105:
            {
                *out_value = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE + MBEDTLS_ERR_OID_NOT_FOUND;
            }
            break;
        case 106:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS+MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 107:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS+MBEDTLS_ERR_ASN1_OUT_OF_DATA;
            }
            break;
        case 108:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS+MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            }
            break;
        case 109:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS+MBEDTLS_ERR_ASN1_INVALID_DATA;
            }
            break;
        case 110:
            {
                *out_value = MBEDTLS_ERR_PEM_INVALID_DATA + MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
            }
            break;
        case 111:
            {
                *out_value = MBEDTLS_ASN1_UTC_TIME;
            }
            break;
        case 112:
            {
                *out_value = MBEDTLS_ASN1_GENERALIZED_TIME;
            }
            break;
        case 113:
            {
                *out_value = MBEDTLS_ASN1_CONTEXT_SPECIFIC;
            }
            break;
        case 114:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_DATE+MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
            }
            break;
        case 115:
            {
                *out_value = MBEDTLS_X509_EXT_KEY_USAGE;
            }
            break;
        case 116:
            {
                *out_value = MBEDTLS_X509_EXT_SUBJECT_ALT_NAME;
            }
            break;
        case 117:
            {
                *out_value = MBEDTLS_ERR_X509_INVALID_EXTENSIONS+MBEDTLS_ERR_ASN1_INVALID_LENGTH;
            }
            break;
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
    
        case 0:
            {
#if defined(MBEDTLS_PEM_PARSE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_RSA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_MD_CAN_SHA1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_MD_CAN_MD5)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_MD_CAN_SHA224)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_MD_CAN_SHA256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_MD_CAN_SHA384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_MD_CAN_SHA512)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 11:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 12:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP192R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 13:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 14:
            {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 15:
            {
#if defined(MBEDTLS_HAVE_TIME_DATE)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 16:
            {
#if defined(MBEDTLS_PKCS1_V15)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 17:
            {
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 18:
            {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 19:
            {
#if !defined(MBEDTLS_HAVE_TIME_DATE)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 20:
            {
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 21:
            {
#if defined(MBEDTLS_X509_USE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 22:
            {
#if defined(MBEDTLS_X509_CRT_PARSE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
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

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509_accessor_ext_types_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_TEST_HOOKS)
    test_x509_crt_parse_cn_inet_pton_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509_parse_san_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_FS_IO) && !defined(MBEDTLS_X509_REMOVE_INFO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509_cert_info_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRL_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_crl_info_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRL_PARSE_C)
    test_mbedtls_x509_crl_parse_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CSR_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_csr_info_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_x509_verify_info_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_X509_CRL_PARSE_C) && defined(MBEDTLS_ECP_RESTARTABLE) && defined(MBEDTLS_ECDSA_C)
    test_x509_verify_restart_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_X509_CRL_PARSE_C)
    test_x509_verify_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_X509_CRL_PARSE_C) && defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    test_x509_verify_ca_cb_failure_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509_verify_callback_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_dn_gets_subject_replace_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_dn_gets_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    test_mbedtls_x509_get_name_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_X509_CREATE_C) && defined(MBEDTLS_X509_USE_C) && defined(MBEDTLS_X509_CRT_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_dn_get_next_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_mbedtls_x509_time_is_past_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_mbedtls_x509_time_is_future_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_FS_IO)
    test_x509parse_crt_file_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_FS_IO)
    test_mbedtls_x509_get_ca_istrue_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509parse_crt_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509parse_crt_cb_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_X509_CRL_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_x509parse_crl_wrapper,
#else
    NULL,
#endif
/* Function Id: 23 */

#if defined(MBEDTLS_X509_CSR_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_csr_parse_wrapper,
#else
    NULL,
#endif
/* Function Id: 24 */

#if defined(MBEDTLS_X509_CSR_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_csr_parse_with_ext_cb_wrapper,
#else
    NULL,
#endif
/* Function Id: 25 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CSR_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_mbedtls_x509_csr_parse_file_wrapper,
#else
    NULL,
#endif
/* Function Id: 26 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_mbedtls_x509_crt_parse_file_wrapper,
#else
    NULL,
#endif
/* Function Id: 27 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_mbedtls_x509_crt_parse_path_wrapper,
#else
    NULL,
#endif
/* Function Id: 28 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_mbedtls_x509_crt_verify_max_wrapper,
#else
    NULL,
#endif
/* Function Id: 29 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_mbedtls_x509_crt_verify_chain_wrapper,
#else
    NULL,
#endif
/* Function Id: 30 */

#if defined(MBEDTLS_X509_USE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)
    test_x509_oid_desc_wrapper,
#else
    NULL,
#endif
/* Function Id: 31 */

#if defined(MBEDTLS_X509_USE_C)
    test_x509_oid_numstr_wrapper,
#else
    NULL,
#endif
/* Function Id: 32 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509_check_key_usage_wrapper,
#else
    NULL,
#endif
/* Function Id: 33 */

#if defined(MBEDTLS_FS_IO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    test_x509_check_extended_key_usage_wrapper,
#else
    NULL,
#endif
/* Function Id: 34 */

#if defined(MBEDTLS_X509_USE_C)
    test_x509_get_time_wrapper,
#else
    NULL,
#endif
/* Function Id: 35 */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    test_x509_parse_rsassa_pss_params_wrapper,
#else
    NULL,
#endif
/* Function Id: 36 */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_FS_IO)
    test_x509_crt_parse_subjectkeyid_wrapper,
#else
    NULL,
#endif
/* Function Id: 37 */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_FS_IO)
    test_x509_crt_parse_authoritykeyid_wrapper,
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
    const char *default_filename = ".\\test_suite_x509parse.datax";
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
