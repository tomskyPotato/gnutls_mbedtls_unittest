#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : .\test_suite_ecp.generated.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/main_test.function
 *      Platform code file  : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/host_test.function
 *      Helper file         : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/helpers.function
 *      Test suite file     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function
 *      Test suite data     : C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/build/mbedtls/tests/suites/test_suite_ecp.generated.data
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

#if defined(MBEDTLS_ECP_LIGHT)
#line 2 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
#include "mbedtls/ecp.h"
#include "ecp_invasive.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"

#include "bignum_core.h"
#include "ecp_invasive.h"
#include "bignum_mod_raw_invasive.h"
#include "constant_time_internal.h"

#define ECP_PF_UNKNOWN     -1

#define ECP_PT_RESET(x)           \
    mbedtls_ecp_point_free(x);    \
    mbedtls_ecp_point_init(x);

/* Auxiliary function to compare two mbedtls_ecp_group objects. */
inline static int mbedtls_ecp_group_cmp(mbedtls_ecp_group *grp1,
                                        mbedtls_ecp_group *grp2)
{
    if (mbedtls_mpi_cmp_mpi(&grp1->P, &grp2->P) != 0) {
        return 1;
    }
    if (mbedtls_mpi_cmp_mpi(&grp1->A, &grp2->A) != 0) {
        return 1;
    }
    if (mbedtls_mpi_cmp_mpi(&grp1->B, &grp2->B) != 0) {
        return 1;
    }
    if (mbedtls_mpi_cmp_mpi(&grp1->N, &grp2->N) != 0) {
        return 1;
    }
    if (mbedtls_ecp_point_cmp(&grp1->G, &grp2->G) != 0) {
        return 1;
    }
    if (grp1->id != grp2->id) {
        return 1;
    }
    if (grp1->pbits != grp2->pbits) {
        return 1;
    }
    if (grp1->nbits != grp2->nbits) {
        return 1;
    }
    if (grp1->h != grp2->h) {
        return 1;
    }
    if (grp1->modp != grp2->modp) {
        return 1;
    }
    if (grp1->t_pre != grp2->t_pre) {
        return 1;
    }
    if (grp1->t_post != grp2->t_post) {
        return 1;
    }
    if (grp1->t_data != grp2->t_data) {
        return 1;
    }
    if (grp1->T_size != grp2->T_size) {
        return 1;
    }
    if (grp1->T != grp2->T) {
        return 1;
    }

    return 0;
}

#line 79 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_invalid_param(void)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    int invalid_fmt = 42;
    size_t olen;
    unsigned char buf[42] = { 0 };

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P);

    TEST_EQUAL(MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
               mbedtls_ecp_point_write_binary(&grp, &P,
                                              invalid_fmt,
                                              &olen,
                                              buf, sizeof(buf)));
    TEST_EQUAL(MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
               mbedtls_ecp_tls_write_point(&grp, &P,
                                           invalid_fmt,
                                           &olen,
                                           buf,
                                           sizeof(buf)));

exit:
    return;
}

static void test_ecp_invalid_param_wrapper( void ** params )
{
    (void)params;

    test_ecp_invalid_param(  );
}
#line 108 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_curve_info(int id, int tls_id, int size, char *name)
{
    const mbedtls_ecp_curve_info *by_id, *by_tls, *by_name;

    by_id   = mbedtls_ecp_curve_info_from_grp_id(id);
    by_tls  = mbedtls_ecp_curve_info_from_tls_id(tls_id);
    by_name = mbedtls_ecp_curve_info_from_name(name);
    TEST_ASSERT(by_id   != NULL);
    TEST_ASSERT(by_tls  != NULL);
    TEST_ASSERT(by_name != NULL);

    TEST_ASSERT(by_id == by_tls);
    TEST_ASSERT(by_id == by_name);

    TEST_ASSERT(by_id->bit_size == size);
    TEST_ASSERT(size <= MBEDTLS_ECP_MAX_BITS);
    TEST_ASSERT(size <= MBEDTLS_ECP_MAX_BYTES * 8);
exit:
    ;
}

static void test_mbedtls_ecp_curve_info_wrapper( void ** params )
{

    test_mbedtls_ecp_curve_info( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, (char *) params[3] );
}
#line 129 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_check_pub(int grp_id, char *x_hex, char *y_hex, char *z_hex,
                   int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, grp_id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&P.X, x_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&P.Y, y_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&P.Z, z_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &P) == ret);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&P);
}

static void test_ecp_check_pub_wrapper( void ** params )
{

    test_ecp_check_pub( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], ((mbedtls_test_argument_t *) params[4])->sint );
}
#if defined(MBEDTLS_ECP_RESTARTABLE)
#line 153 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_test_vect_restart(int id,
                           char *dA_str, char *xA_str, char *yA_str,
                           char *dB_str,  char *xZ_str, char *yZ_str,
                           int max_ops, int min_restarts, int max_restarts)
{
    /*
     * Test for early restart. Based on test vectors like ecp_test_vect(),
     * but for the sake of simplicity only does half of each side. It's
     * important to test both base point and random point, though, as memory
     * management is different in each case.
     *
     * Don't try using too precise bounds for restarts as the exact number
     * will depend on settings such as MBEDTLS_ECP_FIXED_POINT_OPTIM and
     * MBEDTLS_ECP_WINDOW_SIZE, as well as implementation details that may
     * change in the future. A factor 2 is a minimum safety margin.
     *
     * For reference, with Mbed TLS 2.4 and default settings, for P-256:
     * - Random point mult:     ~3250M
     * - Cold base point mult:  ~3300M
     * - Hot base point mult:   ~1100M
     * With MBEDTLS_ECP_WINDOW_SIZE set to 2 (minimum):
     * - Random point mult:     ~3850M
     */
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi dA, xA, yA, dB, xZ, yZ;
    int cnt_restarts;
    int ret;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xZ, xZ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yZ, yZ_str) == 0);

    mbedtls_ecp_set_max_ops((unsigned) max_ops);

    /* Base point case */
    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_mul_restartable(&grp, &R, &dA, &grp.G,
                                          &mbedtls_test_rnd_pseudo_rand, &rnd_info, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yA) == 0);

    TEST_ASSERT(cnt_restarts >= min_restarts);
    TEST_ASSERT(cnt_restarts <= max_restarts);

    /* Non-base point case */
    mbedtls_ecp_copy(&P, &R);
    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_mul_restartable(&grp, &R, &dB, &P,
                                          &mbedtls_test_rnd_pseudo_rand, &rnd_info, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xZ) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yZ) == 0);

    TEST_ASSERT(cnt_restarts >= min_restarts);
    TEST_ASSERT(cnt_restarts <= max_restarts);

    /* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if (min_restarts > 0) {
        ret = mbedtls_ecp_mul_restartable(&grp, &R, &dB, &P,
                                          &mbedtls_test_rnd_pseudo_rand, &rnd_info, &ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_ecp_restart_free(&ctx);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA); mbedtls_mpi_free(&yA);
    mbedtls_mpi_free(&dB); mbedtls_mpi_free(&xZ); mbedtls_mpi_free(&yZ);
}

static void test_ecp_test_vect_restart_wrapper( void ** params )
{

    test_ecp_test_vect_restart( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint, ((mbedtls_test_argument_t *) params[9])->sint );
}
#endif /* MBEDTLS_ECP_RESTARTABLE */
#if defined(MBEDTLS_ECP_RESTARTABLE)
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
#line 252 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_muladd_restart(int id, char *xR_str, char *yR_str,
                        char *u1_str, char *u2_str,
                        char *xQ_str, char *yQ_str,
                        int max_ops, int min_restarts, int max_restarts)
{
    /*
     * Compute R = u1 * G + u2 * Q
     * (test vectors mostly taken from ECDSA intermediate results)
     *
     * See comments at the top of ecp_test_vect_restart()
     */
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, Q;
    mbedtls_mpi u1, u2, xR, yR;
    int cnt_restarts;
    int ret;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);
    mbedtls_mpi_init(&xR); mbedtls_mpi_init(&yR);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&u1, u1_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&u2, u2_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xR, xR_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yR, yR_str) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&Q.X, xQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q.Y, yQ_str) == 0);
    TEST_ASSERT(mbedtls_mpi_lset(&Q.Z, 1) == 0);

    mbedtls_ecp_set_max_ops((unsigned) max_ops);

    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xR) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yR) == 0);

    TEST_ASSERT(cnt_restarts >= min_restarts);
    TEST_ASSERT(cnt_restarts <= max_restarts);

    /* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if (min_restarts > 0) {
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_ecp_restart_free(&ctx);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);
    mbedtls_mpi_free(&xR); mbedtls_mpi_free(&yR);
}

static void test_ecp_muladd_restart_wrapper( void ** params )
{

    test_ecp_muladd_restart( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint, ((mbedtls_test_argument_t *) params[9])->sint );
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
#endif /* MBEDTLS_ECP_RESTARTABLE */
#if defined(MBEDTLS_ECP_C)
#line 323 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_test_vect(int id, char *dA_str, char *xA_str, char *yA_str,
                   char *dB_str, char *xB_str, char *yB_str,
                   char *xZ_str, char *yZ_str)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, yA, dB, xB, yB, xZ, yZ;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA); mbedtls_mpi_init(&dB);
    mbedtls_mpi_init(&xB); mbedtls_mpi_init(&yB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yB, yB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xZ, xZ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yZ, yZ_str) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yA) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xZ) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yZ) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yB) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xZ) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yZ) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA); mbedtls_mpi_free(&yA); mbedtls_mpi_free(&dB);
    mbedtls_mpi_free(&xB); mbedtls_mpi_free(&yB); mbedtls_mpi_free(&xZ); mbedtls_mpi_free(&yZ);
}

static void test_ecp_test_vect_wrapper( void ** params )
{

    test_ecp_test_vect( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], (char *) params[7], (char *) params[8] );
}
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_ECP_C)
#line 380 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_test_vec_x(int id, char *dA_hex, char *xA_hex, char *dB_hex,
                    char *xB_hex, char *xS_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, dB, xB, xS;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xB);
    mbedtls_mpi_init(&xS);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xS, xS_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xS) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xS) == 0);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA);
    mbedtls_mpi_free(&dB); mbedtls_mpi_free(&xB);
    mbedtls_mpi_free(&xS);
}

static void test_ecp_test_vec_x_wrapper( void ** params )
{

    test_ecp_test_vec_x( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], (char *) params[5] );
}
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_ECP_C)
#line 433 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_test_mul(int id, data_t *n_hex,
                  data_t *Px_hex, data_t *Py_hex, data_t *Pz_hex,
                  data_t *nPx_hex, data_t *nPy_hex, data_t *nPz_hex,
                  int expected_ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, nP, R;
    mbedtls_mpi n;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&nP);
    mbedtls_mpi_init(&n);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&n, n_hex->x, n_hex->len) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&P.X, Px_hex->x, Px_hex->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&P.Y, Py_hex->x, Py_hex->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&P.Z, Pz_hex->x, Pz_hex->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&nP.X, nPx_hex->x, nPx_hex->len)
                == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&nP.Y, nPy_hex->x, nPy_hex->len)
                == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&nP.Z, nPz_hex->x, nPz_hex->len)
                == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &n, &P,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info)
                == expected_ret);

    if (expected_ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.X, &R.X) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.Y, &R.Y) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.Z, &R.Z) == 0);
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&P); mbedtls_ecp_point_free(&nP);
    mbedtls_mpi_free(&n);
}

static void test_ecp_test_mul_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};
    data_t data9 = {(uint8_t *) params[9], ((mbedtls_test_argument_t *) params[10])->len};
    data_t data11 = {(uint8_t *) params[11], ((mbedtls_test_argument_t *) params[12])->len};
    data_t data13 = {(uint8_t *) params[13], ((mbedtls_test_argument_t *) params[14])->len};

    test_ecp_test_mul( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, &data5, &data7, &data9, &data11, &data13, ((mbedtls_test_argument_t *) params[15])->sint );
}
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_ECP_C)
#line 482 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_test_mul_rng(int id, data_t *d_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&d, d_hex->x, d_hex->len) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
                                &mbedtls_test_rnd_zero_rand, NULL)
                == MBEDTLS_ERR_ECP_RANDOM_FAILED);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
}

static void test_ecp_test_mul_rng_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_ecp_test_mul_rng( ((mbedtls_test_argument_t *) params[0])->sint, &data1 );
}
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
#if defined(MBEDTLS_ECP_C)
#line 508 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_muladd(int id,
                data_t *u1_bin, data_t *P1_bin,
                data_t *u2_bin, data_t *P2_bin,
                data_t *expected_result)
{
    /* Compute R = u1 * P1 + u2 * P2 */
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P1, P2, R;
    mbedtls_mpi u1, u2;
    uint8_t actual_result[MBEDTLS_ECP_MAX_PT_LEN];
    size_t len;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P1);
    mbedtls_ecp_point_init(&P2);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&u1);
    mbedtls_mpi_init(&u2);

    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, id));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u1, u1_bin->x, u1_bin->len));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u2, u2_bin->x, u2_bin->len));
    TEST_EQUAL(0, mbedtls_ecp_point_read_binary(&grp, &P1,
                                                P1_bin->x, P1_bin->len));
    TEST_EQUAL(0, mbedtls_ecp_point_read_binary(&grp, &P2,
                                                P2_bin->x, P2_bin->len));

    TEST_EQUAL(0, mbedtls_ecp_muladd(&grp, &R, &u1, &P1, &u2, &P2));
    TEST_EQUAL(0, mbedtls_ecp_point_write_binary(
                   &grp, &R, MBEDTLS_ECP_PF_UNCOMPRESSED,
                   &len, actual_result, sizeof(actual_result)));
    TEST_ASSERT(len <= MBEDTLS_ECP_MAX_PT_LEN);

    TEST_MEMORY_COMPARE(expected_result->x, expected_result->len,
                        actual_result, len);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&P1);
    mbedtls_ecp_point_free(&P2);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&u1);
    mbedtls_mpi_free(&u2);
}

static void test_ecp_muladd_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};
    data_t data9 = {(uint8_t *) params[9], ((mbedtls_test_argument_t *) params[10])->len};

    test_ecp_muladd( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3, &data5, &data7, &data9 );
}
#endif /* MBEDTLS_ECP_C */
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
#line 555 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_fast_mod(int id, char *N_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi N, R;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&R);
    mbedtls_ecp_group_init(&grp);

    TEST_ASSERT(mbedtls_test_read_mpi(&N, N_str) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(grp.modp != NULL);

    /*
     * Store correct result before we touch N
     */
    TEST_ASSERT(mbedtls_mpi_mod_mpi(&R, &N, &grp.P) == 0);

    TEST_ASSERT(grp.modp(&N) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&N) <= grp.pbits + 3);

    /*
     * Use mod rather than addition/subtraction in case previous test fails
     */
    TEST_ASSERT(mbedtls_mpi_mod_mpi(&N, &N, &grp.P) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&N, &R) == 0);

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&R);
    mbedtls_ecp_group_free(&grp);
}

static void test_ecp_fast_mod_wrapper( void ** params )
{

    test_ecp_fast_mod( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1] );
}
#line 588 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_write_binary(int id, char *x, char *y, char *z, int format,
                      data_t *out, int blen, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_ecp_keypair key;
    unsigned char buf[256];
    size_t olen;

    memset(buf, 0, sizeof(buf));

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_ecp_keypair_init(&key);

    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    TEST_EQUAL(mbedtls_test_read_mpi(&P.X, x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&P.Y, y), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&P.Z, z), 0);

    TEST_EQUAL(mbedtls_ecp_point_write_binary(&grp, &P, format,
                                              &olen, buf, blen), ret);
    if (ret == 0) {
        TEST_LE_U(olen, MBEDTLS_ECP_MAX_PT_LEN);
        ASSERT_COMPARE(buf, olen,
                       out->x, out->len);
    }

    memset(buf, 0, blen);
    TEST_EQUAL(mbedtls_ecp_set_public_key(grp.id, &key, &P), 0);
    TEST_EQUAL(mbedtls_ecp_write_public_key(&key, format,
                                            &olen, buf, blen), ret);
    if (ret == 0) {
        ASSERT_COMPARE(buf, olen,
                       out->x, out->len);
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&P);
    mbedtls_ecp_keypair_free(&key);
}

static void test_ecp_write_binary_wrapper( void ** params )
{
    data_t data5 = {(uint8_t *) params[5], ((mbedtls_test_argument_t *) params[6])->len};

    test_ecp_write_binary( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], ((mbedtls_test_argument_t *) params[4])->sint, &data5, ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint );
}
#line 632 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_read_binary(int id, data_t *buf, char *x, char *y, char *z,
                     int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;


    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, x) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Z, z) == 0);

    TEST_ASSERT(mbedtls_ecp_point_read_binary(&grp, &P, buf->x, buf->len) == ret);

    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.X, &X) == 0);
        if (mbedtls_ecp_get_type(&grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
            TEST_ASSERT(mbedtls_mpi_cmp_int(&Y, 0) == 0);
            TEST_ASSERT(P.Y.p == NULL);
            TEST_ASSERT(mbedtls_mpi_cmp_int(&Z, 1) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_int(&P.Z, 1) == 0);
        } else {
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Z, &Z) == 0);

            if (buf->x[0] == 0x04 &&
                /* (reading compressed format supported only for
                 *  Short Weierstrass curves with prime p where p = 3 mod 4) */
                id != MBEDTLS_ECP_DP_SECP224R1 &&
                id != MBEDTLS_ECP_DP_SECP224K1) {
                /* re-encode in compressed format and test read again */
                mbedtls_mpi_free(&P.Y);
                buf->x[0] = 0x02 + mbedtls_mpi_get_bit(&Y, 0);
                TEST_ASSERT(mbedtls_ecp_point_read_binary(&grp, &P, buf->x, buf->len/2+1) == 0);
                TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
            }
        }
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}

static void test_ecp_read_binary_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_ecp_read_binary( ((mbedtls_test_argument_t *) params[0])->sint, &data1, (char *) params[3], (char *) params[4], (char *) params[5], ((mbedtls_test_argument_t *) params[6])->sint );
}
#line 683 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_tls_read_point(int id, data_t *buf, char *x, char *y,
                                char *z, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;
    const unsigned char *vbuf = buf->x;


    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, x) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Z, z) == 0);

    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &P, &vbuf, buf->len) == ret);

    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.X, &X) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Z, &Z) == 0);
        TEST_ASSERT((uint32_t) (vbuf - buf->x) == buf->len);
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}

static void test_mbedtls_ecp_tls_read_point_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_mbedtls_ecp_tls_read_point( ((mbedtls_test_argument_t *) params[0])->sint, &data1, (char *) params[3], (char *) params[4], (char *) params[5], ((mbedtls_test_argument_t *) params[6])->sint );
}
#line 717 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_tls_write_read_point(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt;
    unsigned char buf[256];
    const unsigned char *vbuf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pt);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    memset(buf, 0x00, sizeof(buf)); vbuf = buf;
    TEST_ASSERT(mbedtls_ecp_tls_write_point(&grp, &grp.G,
                                            MBEDTLS_ECP_PF_COMPRESSED, &olen, buf, 256) == 0);
    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &pt, &vbuf, olen) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.X, &pt.X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.Y, &pt.Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.Z, &pt.Z) == 0);
    TEST_ASSERT(vbuf == buf + olen);

    memset(buf, 0x00, sizeof(buf)); vbuf = buf;
    TEST_ASSERT(mbedtls_ecp_tls_write_point(&grp, &grp.G,
                                            MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, 256) == 0);
    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &pt, &vbuf, olen) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.X, &pt.X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.Y, &pt.Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.Z, &pt.Z) == 0);
    TEST_ASSERT(vbuf == buf + olen);

    memset(buf, 0x00, sizeof(buf)); vbuf = buf;
    TEST_ASSERT(mbedtls_ecp_set_zero(&pt) == 0);
    TEST_ASSERT(mbedtls_ecp_tls_write_point(&grp, &pt,
                                            MBEDTLS_ECP_PF_COMPRESSED, &olen, buf, 256) == 0);
    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &pt, &vbuf, olen) == 0);
    TEST_ASSERT(mbedtls_ecp_is_zero(&pt));
    TEST_ASSERT(vbuf == buf + olen);

    memset(buf, 0x00, sizeof(buf)); vbuf = buf;
    TEST_ASSERT(mbedtls_ecp_set_zero(&pt) == 0);
    TEST_ASSERT(mbedtls_ecp_tls_write_point(&grp, &pt,
                                            MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, 256) == 0);
    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &pt, &vbuf, olen) == 0);
    TEST_ASSERT(mbedtls_ecp_is_zero(&pt));
    TEST_ASSERT(vbuf == buf + olen);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&pt);
}

static void test_ecp_tls_write_read_point_wrapper( void ** params )
{

    test_ecp_tls_write_read_point( ((mbedtls_test_argument_t *) params[0])->sint );
}
#line 771 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_tls_read_group(data_t *buf, int result, int bits,
                                int record_len)
{
    mbedtls_ecp_group grp;
    const unsigned char *vbuf = buf->x;
    int ret;

    mbedtls_ecp_group_init(&grp);

    ret = mbedtls_ecp_tls_read_group(&grp, &vbuf, buf->len);

    TEST_ASSERT(ret == result);
    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_bitlen(&grp.P) == (size_t) bits);
        TEST_ASSERT(vbuf - buf->x ==  record_len);
    }

exit:
    mbedtls_ecp_group_free(&grp);
}

static void test_mbedtls_ecp_tls_read_group_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_mbedtls_ecp_tls_read_group( &data0, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#line 794 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_tls_write_read_group(int id)
{
    mbedtls_ecp_group grp1, grp2;
    unsigned char buf[10];
    const unsigned char *vbuf = buf;
    size_t len;
    int ret;

    mbedtls_ecp_group_init(&grp1);
    mbedtls_ecp_group_init(&grp2);
    memset(buf, 0x00, sizeof(buf));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp1, id) == 0);

    TEST_ASSERT(mbedtls_ecp_tls_write_group(&grp1, &len, buf, 10) == 0);
    ret = mbedtls_ecp_tls_read_group(&grp2, &vbuf, len);
    TEST_ASSERT(ret == 0);

    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp1.N, &grp2.N) == 0);
        TEST_ASSERT(grp1.id == grp2.id);
    }

exit:
    mbedtls_ecp_group_free(&grp1);
    mbedtls_ecp_group_free(&grp2);
}

static void test_ecp_tls_write_read_group_wrapper( void ** params )
{

    test_ecp_tls_write_read_group( ((mbedtls_test_argument_t *) params[0])->sint );
}
#line 824 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_group_metadata(int id, int bit_size, int crv_type,
                                char *P, char *A, char *B,
                                char *G_x, char *G_y, char *N,
                                int tls_id)
{
    mbedtls_ecp_group grp, grp_read, grp_cpy;
    const mbedtls_ecp_group_id *g_id;
    mbedtls_ecp_group_id read_g_id;
    const mbedtls_ecp_curve_info *crv, *crv_tls_id, *crv_name;

    mbedtls_mpi exp_P, exp_A, exp_B, exp_G_x, exp_G_y, exp_N;

    unsigned char buf[3], ecparameters[3] = { 3, 0, tls_id };
    const unsigned char *vbuf = buf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_init(&grp_read);
    mbedtls_ecp_group_init(&grp_cpy);

    mbedtls_mpi_init(&exp_P);
    mbedtls_mpi_init(&exp_A);
    mbedtls_mpi_init(&exp_B);
    mbedtls_mpi_init(&exp_G_x);
    mbedtls_mpi_init(&exp_G_y);
    mbedtls_mpi_init(&exp_N);

    // Read expected parameters
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_P, P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_A, A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_x, G_x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_N, N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_B, B), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_y, G_y), 0);

    // Convert exp_A to internal representation (A+2)/4
    if (crv_type == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        TEST_EQUAL(mbedtls_mpi_add_int(&exp_A, &exp_A, 2), 0);
        TEST_EQUAL(mbedtls_mpi_div_int(&exp_A, NULL, &exp_A, 4), 0);
    }

    // Load group
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    // Compare group with expected parameters
    // A is NULL for SECPxxxR1 curves
    // B and G_y are NULL for curve25519 and curve448
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_P, &grp.P), 0);
    if (*A != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_A, &grp.A), 0);
    }
    if (*B != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_B, &grp.B), 0);
    }
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_G_x, &grp.G.X), 0);
    if (*G_y != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_G_y, &grp.G.Y), 0);
    }
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_N, &grp.N), 0);

    // Load curve info and compare with known values
    crv = mbedtls_ecp_curve_info_from_grp_id(id);
    TEST_EQUAL(crv->grp_id, id);
    TEST_EQUAL(crv->bit_size, bit_size);
    TEST_EQUAL(crv->tls_id, tls_id);

    // Load curve from TLS ID and name, and compare IDs
    crv_tls_id = mbedtls_ecp_curve_info_from_tls_id(crv->tls_id);
    crv_name = mbedtls_ecp_curve_info_from_name(crv->name);
    TEST_EQUAL(crv_tls_id->grp_id, id);
    TEST_EQUAL(crv_name->grp_id, id);

    // Validate write_group against test data
    TEST_EQUAL(mbedtls_ecp_tls_write_group(&grp, &olen,
                                           buf, sizeof(buf)),
               0);
    TEST_EQUAL(mbedtls_test_hexcmp(buf, ecparameters, olen,
                                   sizeof(ecparameters)),
               0);

    // Read group from buffer and compare with expected ID
    TEST_EQUAL(mbedtls_ecp_tls_read_group_id(&read_g_id, &vbuf, olen),
               0);
    TEST_EQUAL(read_g_id, id);
    vbuf = buf;
    TEST_EQUAL(mbedtls_ecp_tls_read_group(&grp_read, &vbuf, olen),
               0);
    TEST_EQUAL(grp_read.id, id);

    // Check curve type, and if it can be used for ECDH/ECDSA
    TEST_EQUAL(mbedtls_ecp_get_type(&grp), crv_type);
#if defined(MBEDTLS_ECDH_C)
    TEST_EQUAL(mbedtls_ecdh_can_do(id), 1);
#endif
#if defined(MBEDTLS_ECDSA_C)
    TEST_EQUAL(mbedtls_ecdsa_can_do(id),
               crv_type == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS);
#endif

    // Copy group and compare with original
    TEST_EQUAL(mbedtls_ecp_group_copy(&grp_cpy, &grp), 0);
    TEST_EQUAL(mbedtls_ecp_group_cmp(&grp, &grp_cpy), 0);

    // Check curve is in curve list and group ID list
    for (crv = mbedtls_ecp_curve_list();
         crv->grp_id != MBEDTLS_ECP_DP_NONE &&
         crv->grp_id != (unsigned) id;
         crv++) {
        ;
    }
    TEST_EQUAL(crv->grp_id, id);
    for (g_id = mbedtls_ecp_grp_id_list();
         *g_id != MBEDTLS_ECP_DP_NONE && *g_id != (unsigned) id;
         g_id++) {
        ;
    }
    TEST_EQUAL(*g_id, (unsigned) id);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_group_free(&grp_cpy);
    mbedtls_ecp_group_free(&grp_read);
    mbedtls_mpi_free(&exp_P); mbedtls_mpi_free(&exp_A);
    mbedtls_mpi_free(&exp_B); mbedtls_mpi_free(&exp_G_x);
    mbedtls_mpi_free(&exp_G_y); mbedtls_mpi_free(&exp_N);
}

static void test_mbedtls_ecp_group_metadata_wrapper( void ** params )
{

    test_mbedtls_ecp_group_metadata( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], (char *) params[7], (char *) params[8], ((mbedtls_test_argument_t *) params[9])->sint );
}
#line 952 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_check_privkey(int id, char *key_hex, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, key_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == ret);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
}

static void test_mbedtls_ecp_check_privkey_wrapper( void ** params )
{

    test_mbedtls_ecp_check_privkey( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint );
}
#if defined(MBEDTLS_ECP_C)
#line 972 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_check_pub_priv(int id_pub, char *Qx_pub, char *Qy_pub,
                                int id, char *d, char *Qx, char *Qy,
                                int ret)
{
    mbedtls_ecp_keypair pub, prv;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_keypair_init(&pub);
    mbedtls_ecp_keypair_init(&prv);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    if (id_pub != MBEDTLS_ECP_DP_NONE) {
        TEST_ASSERT(mbedtls_ecp_group_load(&pub.grp, id_pub) == 0);
    }
    TEST_ASSERT(mbedtls_ecp_point_read_string(&pub.Q, 16, Qx_pub, Qy_pub) == 0);

    if (id != MBEDTLS_ECP_DP_NONE) {
        TEST_ASSERT(mbedtls_ecp_group_load(&prv.grp, id) == 0);
    }
    TEST_ASSERT(mbedtls_ecp_point_read_string(&prv.Q, 16, Qx, Qy) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&prv.d, d) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pub_priv(&pub, &prv,
                                           &mbedtls_test_rnd_pseudo_rand, &rnd_info) == ret);

exit:
    mbedtls_ecp_keypair_free(&pub);
    mbedtls_ecp_keypair_free(&prv);
}

static void test_mbedtls_ecp_check_pub_priv_wrapper( void ** params )
{

    test_mbedtls_ecp_check_pub_priv( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], ((mbedtls_test_argument_t *) params[3])->sint, (char *) params[4], (char *) params[5], (char *) params[6], ((mbedtls_test_argument_t *) params[7])->sint );
}
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_ECP_C)
#line 1004 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_calc_public(int grp_id, data_t *private_data,
                     int expected_ret, data_t *expected_public)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_test_rnd_pseudo_info rnd_info;
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_EQUAL(mbedtls_ecp_group_load(&key.grp, grp_id), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary(&key.d,
                                       private_data->x, private_data->len), 0);

    TEST_EQUAL(mbedtls_ecp_keypair_calc_public(&key,
                                               &mbedtls_test_rnd_pseudo_rand, &rnd_info),
               expected_ret);

    if (expected_ret == 0) {
        TEST_EQUAL(mbedtls_ecp_check_pub_priv(&key, &key,
                                              &mbedtls_test_rnd_pseudo_rand, &rnd_info),
                   0);
        unsigned char buf[MBEDTLS_ECP_MAX_PT_LEN];
        size_t length;
        TEST_EQUAL(mbedtls_ecp_point_write_binary(&key.grp, &key.Q,
                                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                  &length, buf, sizeof(buf)),
                   0);
        ASSERT_COMPARE(expected_public->x, expected_public->len, buf, length);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
}

static void test_ecp_calc_public_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};

    test_ecp_calc_public( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, &data4 );
}
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_ECP_C)
#line 1039 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_gen_keypair(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &Q) == 0);
    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
}

static void test_mbedtls_ecp_gen_keypair_wrapper( void ** params )
{

    test_mbedtls_ecp_gen_keypair( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_ECP_C)
#line 1068 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_gen_key(int id)
{
    mbedtls_ecp_keypair key;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_keypair_init(&key);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_gen_key(id, &key,
                                    &mbedtls_test_rnd_pseudo_rand,
                                    &rnd_info) == 0);

    TEST_EQUAL(mbedtls_ecp_keypair_get_group_id(&key), id);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&key.grp, &key.Q) == 0);
    TEST_ASSERT(mbedtls_ecp_check_privkey(&key.grp, &key.d) == 0);

exit:
    mbedtls_ecp_keypair_free(&key);
}

static void test_mbedtls_ecp_gen_key_wrapper( void ** params )
{

    test_mbedtls_ecp_gen_key( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_ECP_C */
#line 1090 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_set_public_key_group_check(int grp_id, int expected_ret)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    TEST_EQUAL(mbedtls_ecp_set_public_key(grp_id, &key, &Q),
               expected_ret);

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_point_free(&Q);
}

static void test_ecp_set_public_key_group_check_wrapper( void ** params )
{

    test_ecp_set_public_key_group_check( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint );
}
#line 1107 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_set_public_key_good(int grp_id, data_t *public_data)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    TEST_EQUAL(mbedtls_ecp_group_load(&grp, grp_id), 0);
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&grp, &Q,
                                             public_data->x, public_data->len),
               0);

    /* Freshly initialized key */
    TEST_EQUAL(mbedtls_ecp_set_public_key(grp_id, &key, &Q), 0);
    TEST_EQUAL(key.grp.id, grp_id);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &Q), 0);

    /* Key with a public key already set to a different value */
    TEST_EQUAL(mbedtls_mpi_add_int(&key.Q.X, &key.Q.X, 1), 0);
    TEST_EQUAL(mbedtls_mpi_add_int(&key.Q.Y, &key.Q.Y, 1), 0);
    TEST_EQUAL(mbedtls_mpi_add_int(&key.Q.Z, &key.Q.Z, 1), 0);
    TEST_EQUAL(mbedtls_ecp_set_public_key(grp_id, &key, &Q), 0);
    TEST_EQUAL(key.grp.id, grp_id);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &Q), 0);

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
}

static void test_ecp_set_public_key_good_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_ecp_set_public_key_good( ((mbedtls_test_argument_t *) params[0])->sint, &data1 );
}
#line 1142 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_set_public_key_after_private(int private_grp_id, data_t *private_data,
                                      int public_grp_id, data_t *public_data)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi d;
    mbedtls_mpi_init(&d);

    TEST_EQUAL(mbedtls_ecp_group_load(&grp, public_grp_id), 0);
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&grp, &Q,
                                             public_data->x, public_data->len),
               0);
    TEST_EQUAL(mbedtls_ecp_read_key(private_grp_id, &key,
                                    private_data->x, private_data->len),
               0);
    TEST_EQUAL(mbedtls_mpi_copy(&d, &key.d), 0);

    int ret = mbedtls_ecp_set_public_key(public_grp_id, &key, &Q);

    if (private_grp_id == public_grp_id) {
        TEST_EQUAL(ret, 0);
        TEST_EQUAL(key.grp.id, public_grp_id);
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &Q), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&d, &key.d), 0);
    } else {
        TEST_EQUAL(ret, MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
}

static void test_ecp_set_public_key_after_private_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};

    test_ecp_set_public_key_after_private( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, &data4 );
}
#line 1183 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_mbedtls_ecp_read_key(int grp_id, data_t *in_key, int expected, int canonical)
{
    int ret = 0;
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_keypair key2;
    mbedtls_ecp_keypair_init(&key2);

    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.X, 1), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Y, 2), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Z, 3), 0);

    ret = mbedtls_ecp_read_key(grp_id, &key, in_key->x, in_key->len);
    TEST_ASSERT(ret == expected);

    if (expected == 0) {
        TEST_EQUAL(mbedtls_ecp_keypair_get_group_id(&key), grp_id);
        ret = mbedtls_ecp_check_privkey(&key.grp, &key.d);
        TEST_ASSERT(ret == 0);

        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.X, 1), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Y, 2), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Z, 3), 0);

        if (canonical && in_key->len == (key.grp.nbits + 7) / 8) {
            unsigned char buf[MBEDTLS_ECP_MAX_BYTES];
            size_t length = 0xdeadbeef;

            TEST_EQUAL(mbedtls_ecp_write_key_ext(&key,
                                                 &length, buf, in_key->len), 0);
            TEST_MEMORY_COMPARE(in_key->x, in_key->len,
                                buf, length);

#if defined(MBEDTLS_TEST_DEPRECATED)
            memset(buf, 0, sizeof(buf));
            TEST_EQUAL(mbedtls_ecp_write_key(&key, buf, in_key->len), 0);
            TEST_MEMORY_COMPARE(in_key->x, in_key->len,
                                buf, in_key->len);
#endif /* MBEDTLS_TEST_DEPRECATED */
        } else {
            unsigned char export1[MBEDTLS_ECP_MAX_BYTES];
            unsigned char export2[MBEDTLS_ECP_MAX_BYTES];

            size_t length1 = 0xdeadbeef;
            TEST_EQUAL(mbedtls_ecp_write_key_ext(&key, &length1,
                                                 export1, sizeof(export1)), 0);
            TEST_EQUAL(mbedtls_ecp_read_key(grp_id, &key2, export1, length1),
                       expected);
            size_t length2 = 0xdeadbeef;
            TEST_EQUAL(mbedtls_ecp_write_key_ext(&key2, &length2,
                                                 export2, sizeof(export2)), 0);
            TEST_MEMORY_COMPARE(export1, length1,
                                export2, length2);

#if defined(MBEDTLS_TEST_DEPRECATED)
            memset(export1, 0, sizeof(export1));
            memset(export2, 0, sizeof(export2));
            TEST_EQUAL(mbedtls_ecp_write_key(&key, export1, in_key->len), 0);
            TEST_EQUAL(mbedtls_ecp_read_key(grp_id, &key2, export1, in_key->len),
                       expected);
            TEST_EQUAL(mbedtls_ecp_write_key(&key2, export2, in_key->len), 0);
            TEST_MEMORY_COMPARE(export1, in_key->len,
                                export2, in_key->len);
#endif /* MBEDTLS_TEST_DEPRECATED */
        }
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_keypair_free(&key2);
}

static void test_mbedtls_ecp_read_key_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_mbedtls_ecp_read_key( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#if defined(MBEDTLS_TEST_DEPRECATED)
#line 1257 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_write_key(int grp_id, data_t *in_key,
                   int exported_size, int expected_ret)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    unsigned char *exported = NULL;

    TEST_EQUAL(mbedtls_ecp_read_key(grp_id, &key, in_key->x, in_key->len), 0);

    TEST_CALLOC(exported, exported_size);
    TEST_EQUAL(mbedtls_ecp_write_key(&key, exported, exported_size),
               expected_ret);

    if (expected_ret == 0) {
        size_t length = (key.grp.nbits + 7) / 8;
        const unsigned char *key_start = NULL;
        const unsigned char *zeros_start = NULL;
        switch (mbedtls_ecp_get_type(&key.grp)) {
            case MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS:
                if ((size_t) exported_size < length) {
                    length = exported_size;
                }
                key_start = exported + exported_size - length;
                zeros_start = exported;
                break;
            case MBEDTLS_ECP_TYPE_MONTGOMERY:
                TEST_LE_U(length, exported_size);
                key_start = exported;
                zeros_start = exported + length;
                break;
            default:
                TEST_FAIL("Unknown ECP curve type");
                break;
        }

        if (length < in_key->len) {
            /* Shorter output (only possible with Weierstrass keys) */
            for (size_t i = 0; i < in_key->len - length; i++) {
                mbedtls_test_set_step(i);
                TEST_EQUAL(in_key->x[i], 0);
            }
            TEST_MEMORY_COMPARE(in_key->x + in_key->len - length, length,
                                key_start, length);
        } else {
            TEST_MEMORY_COMPARE(in_key->x, in_key->len,
                                key_start, length);
            for (size_t i = 0; i < exported_size - length; i++) {
                mbedtls_test_set_step(i);
                TEST_EQUAL(zeros_start[i], 0);
            }
        }
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_free(exported);
}

static void test_ecp_write_key_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_ecp_write_key( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_TEST_DEPRECATED */
#line 1317 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_write_key_ext(int grp_id, data_t *in_key,
                       int exported_size, int expected_ret)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    unsigned char *exported = NULL;

    if (in_key->len != 0) {
        TEST_EQUAL(mbedtls_ecp_read_key(grp_id, &key, in_key->x, in_key->len), 0);
    } else if (grp_id != MBEDTLS_ECP_DP_NONE) {
        TEST_EQUAL(mbedtls_ecp_group_load(&key.grp, grp_id), 0);
    }

    TEST_CALLOC(exported, exported_size);
    size_t olen = 0xdeadbeef;
    TEST_EQUAL(mbedtls_ecp_write_key_ext(&key, &olen, exported, exported_size),
               expected_ret);

    if (expected_ret == 0) {
        TEST_EQUAL(olen, (key.grp.nbits + 7) / 8);
        TEST_LE_U(olen, MBEDTLS_ECP_MAX_BYTES);
        TEST_MEMORY_COMPARE(in_key->x, in_key->len,
                            exported, olen);
    } else {
        /* Robustness check: even in the error case, insist that olen is less
         * than the buffer size. */
        TEST_LE_U(olen, exported_size);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_free(exported);
}

static void test_ecp_write_key_ext_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_ecp_write_key_ext( ((mbedtls_test_argument_t *) params[0])->sint, &data1, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
#if defined(MBEDTLS_ECP_LIGHT)
#line 1353 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_genkey_mx_known_answer(int bits, data_t *seed, data_t *expected)
{
    mbedtls_test_rnd_buf_info rnd_info;
    mbedtls_mpi d;
    int ret;
    uint8_t *actual = NULL;

    mbedtls_mpi_init(&d);
    rnd_info.buf = seed->x;
    rnd_info.length = seed->len;
    rnd_info.fallback_f_rng = NULL;
    rnd_info.fallback_p_rng = NULL;

    TEST_CALLOC(actual, expected->len);

    ret = mbedtls_ecp_gen_privkey_mx(bits, &d,
                                     mbedtls_test_rnd_buffer_rand, &rnd_info);

    if (expected->len == 0) {
        /* Expecting an error (happens if there isn't enough randomness) */
        TEST_ASSERT(ret != 0);
    } else {
        TEST_EQUAL(ret, 0);
        TEST_EQUAL((size_t) bits + 1, mbedtls_mpi_bitlen(&d));
        TEST_EQUAL(0, mbedtls_mpi_write_binary(&d, actual, expected->len));
        /* Test the exact result. This assumes that the output of the
         * RNG is used in a specific way, which is overly constraining.
         * The advantage is that it's easier to test the expected properties
         * of the generated key:
         * - The most significant bit must be at a specific positions
         *   (can be enforced by checking the bit-length).
         * - The least significant bits must have specific values
         *   (can be enforced by checking these bits).
         * - Other bits must be random (by testing with different RNG outputs,
         *   we validate that those bits are indeed influenced by the RNG). */
        TEST_MEMORY_COMPARE(expected->x, expected->len,
                            actual, expected->len);
    }

exit:
    mbedtls_free(actual);
    mbedtls_mpi_free(&d);
}

static void test_genkey_mx_known_answer_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};

    test_genkey_mx_known_answer( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3 );
}
#endif /* MBEDTLS_ECP_LIGHT */
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */
#endif /* MBEDTLS_TEST_HOOKS */
#line 1399 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_set_zero(int id, data_t *P_bin)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt, zero_pt, nonzero_pt;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pt);
    mbedtls_ecp_point_init(&zero_pt);
    mbedtls_ecp_point_init(&nonzero_pt);

    // Set zero and non-zero points for comparison
    TEST_EQUAL(mbedtls_ecp_set_zero(&zero_pt), 0);
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&grp, &nonzero_pt,
                                             P_bin->x, P_bin->len), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&zero_pt), 1);
    TEST_EQUAL(mbedtls_ecp_is_zero(&nonzero_pt), 0);

    // Test initialized point
    TEST_EQUAL(mbedtls_ecp_set_zero(&pt), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&pt), 1);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&zero_pt, &pt), 0);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&nonzero_pt, &zero_pt),
               MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // Test zeroed point
    TEST_EQUAL(mbedtls_ecp_set_zero(&pt), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&pt), 1);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&zero_pt, &pt), 0);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&nonzero_pt, &pt),
               MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // Set point to non-zero value
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&grp, &pt,
                                             P_bin->x, P_bin->len), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&pt), 0);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&zero_pt, &pt),
               MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&nonzero_pt, &pt), 0);

    // Test non-zero point
    TEST_EQUAL(mbedtls_ecp_set_zero(&pt), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&pt), 1);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&zero_pt, &pt), 0);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&nonzero_pt, &pt),
               MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // Test freed non-zero point
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&grp, &pt,
                                             P_bin->x, P_bin->len), 0);
    mbedtls_ecp_point_free(&pt);
    TEST_EQUAL(mbedtls_ecp_set_zero(&pt), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&pt), 1);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&zero_pt, &pt), 0);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&nonzero_pt, &pt),
               MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&pt);
    mbedtls_ecp_point_free(&zero_pt);
    mbedtls_ecp_point_free(&nonzero_pt);
}

static void test_ecp_set_zero_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};

    test_ecp_set_zero( ((mbedtls_test_argument_t *) params[0])->sint, &data1 );
}
#if defined(MBEDTLS_SELF_TEST)
#line 1465 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_selftest(void)
{
    TEST_ASSERT(mbedtls_ecp_self_test(1) == 0);
exit:
    ;
}

static void test_ecp_selftest_wrapper( void ** params )
{
    (void)params;

    test_ecp_selftest(  );
}
#endif /* MBEDTLS_SELF_TEST */
#line 1472 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_export(int id, char *Qx, char *Qy, char *d, int expected_ret, int invalid_grp)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_group export_grp;
    mbedtls_mpi export_d;
    mbedtls_ecp_point export_Q;

    mbedtls_ecp_group_init(&export_grp);
    mbedtls_ecp_group_init(&key.grp);
    mbedtls_mpi_init(&export_d);
    mbedtls_ecp_point_init(&export_Q);

    mbedtls_ecp_keypair_init(&key);
    if (invalid_grp == 0) {
        TEST_ASSERT(mbedtls_ecp_group_load(&key.grp, id) == 0);
    }
    TEST_ASSERT(mbedtls_ecp_point_read_string(&key.Q, 16, Qx, Qy) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&key.d, d) == 0);

    TEST_EQUAL(mbedtls_ecp_export(&key, &export_grp,
                                  &export_d, &export_Q), expected_ret);

    if (expected_ret == 0) {
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &export_Q), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&key.d, &export_d), 0);
        TEST_EQUAL(mbedtls_ecp_group_cmp(&key.grp, &export_grp), 0);

        /* Check consistency with the group id */
        TEST_EQUAL(export_grp.id,
                   mbedtls_ecp_keypair_get_group_id(&key));

        /* Test null arguments: grp only */
        mbedtls_ecp_group_free(&export_grp);
        mbedtls_ecp_group_init(&export_grp);
        TEST_EQUAL(mbedtls_ecp_export(&key, &export_grp, NULL, NULL), 0);
        TEST_EQUAL(mbedtls_ecp_group_cmp(&key.grp, &export_grp), 0);

        /* Test null arguments: d only */
        mbedtls_mpi_free(&export_d);
        mbedtls_mpi_init(&export_d);
        TEST_EQUAL(mbedtls_ecp_export(&key, NULL, &export_d, NULL), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&key.d, &export_d), 0);

        /* Test null arguments: Q only */
        mbedtls_ecp_point_free(&export_Q);
        mbedtls_ecp_point_init(&export_Q);
        TEST_EQUAL(mbedtls_ecp_export(&key, NULL, NULL, &export_Q), 0);
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &export_Q), 0);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_group_free(&export_grp);
    mbedtls_mpi_free(&export_d);
    mbedtls_ecp_point_free(&export_Q);
}

static void test_ecp_export_wrapper( void ** params )
{

    test_ecp_export( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3], ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint );
}
#line 1531 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_check_order(int id, char *expected_order_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi expected_n;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&expected_n);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&expected_n, expected_order_hex) == 0);

    // check sign bits are well-formed (i.e. 1 or -1) - see #5810
    TEST_ASSERT(grp.N.s == -1 || grp.N.s == 1);
    TEST_ASSERT(expected_n.s == -1 || expected_n.s == 1);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.N, &expected_n) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&expected_n);
}

static void test_ecp_check_order_wrapper( void ** params )
{

    test_ecp_check_order( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1] );
}
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
#line 1555 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_mod_p_generic_raw(int curve_id,
                           char *input_N,
                           char *input_X,
                           char *result)
{
    mbedtls_mpi_uint *X = NULL;
    mbedtls_mpi_uint *N = NULL;
    mbedtls_mpi_uint *res = NULL;
    size_t limbs_X;
    size_t limbs_N;
    size_t limbs_res;

    size_t bytes;
    size_t limbs;
    size_t curve_bits;
    int (*curve_func)(mbedtls_mpi_uint *X, size_t X_limbs);

    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_modulus_init(&m);

    TEST_EQUAL(mbedtls_test_read_mpi_core(&X,   &limbs_X,   input_X), 0);
    TEST_EQUAL(mbedtls_test_read_mpi_core(&N,   &limbs_N,   input_N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi_core(&res, &limbs_res, result),  0);
    bytes = limbs_N * sizeof(mbedtls_mpi_uint);

    switch (curve_id) {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) && defined(MBEDTLS_ECP_NIST_OPTIM)
        case MBEDTLS_ECP_DP_SECP192R1:
            limbs = BITS_TO_LIMBS(192) * 2;
            curve_bits = 192;
            curve_func = &mbedtls_ecp_mod_p192_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) && defined(MBEDTLS_ECP_NIST_OPTIM)
        case MBEDTLS_ECP_DP_SECP224R1:
            limbs = BITS_TO_LIMBS(224) * 2;
            curve_bits = 224;
            curve_func = &mbedtls_ecp_mod_p224_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) && defined(MBEDTLS_ECP_NIST_OPTIM)
        case MBEDTLS_ECP_DP_SECP256R1:
            limbs = BITS_TO_LIMBS(256) * 2;
            curve_bits = 256;
            curve_func = &mbedtls_ecp_mod_p256_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_ECP_NIST_OPTIM)
        case MBEDTLS_ECP_DP_SECP384R1:
            limbs = BITS_TO_LIMBS(384) * 2;
            curve_bits = 384;
            curve_func = &mbedtls_ecp_mod_p384_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) && defined(MBEDTLS_ECP_NIST_OPTIM)
        case MBEDTLS_ECP_DP_SECP521R1:
            limbs = BITS_TO_LIMBS(521) * 2;
            curve_bits = 521;
            curve_func = &mbedtls_ecp_mod_p521_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192K1:
            limbs = BITS_TO_LIMBS(192) * 2;
            curve_bits = 192;
            curve_func = &mbedtls_ecp_mod_p192k1_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224K1:
            limbs = BITS_TO_LIMBS(224) * 2;
            curve_bits = 224;
            curve_func = &mbedtls_ecp_mod_p224k1_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256K1:
            limbs = BITS_TO_LIMBS(256) * 2;
            curve_bits = 256;
            curve_func = &mbedtls_ecp_mod_p256k1_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        case MBEDTLS_ECP_DP_CURVE25519:
            limbs = BITS_TO_LIMBS(255) * 2;
            curve_bits = 255;
            curve_func = &mbedtls_ecp_mod_p255_raw;
            break;
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        case MBEDTLS_ECP_DP_CURVE448:
            limbs = BITS_TO_LIMBS(448) * 2;
            curve_bits = 448;
            curve_func = &mbedtls_ecp_mod_p448_raw;
            break;
#endif
        default:
            mbedtls_test_fail("Unsupported curve_id", __LINE__, __FILE__);
            goto exit;
    }

    TEST_EQUAL(limbs_X, limbs);
    TEST_EQUAL(limbs_res, limbs_N);

    TEST_EQUAL(mbedtls_mpi_mod_modulus_setup(
                   &m, N, limbs_N), 0);

    TEST_EQUAL((*curve_func)(X, limbs_X), 0);

    mbedtls_mpi_mod_raw_fix_quasi_reduction(X, &m);
    TEST_LE_U(mbedtls_mpi_core_bitlen(X, limbs_X), curve_bits);
    TEST_MEMORY_COMPARE(X, bytes, res, bytes);

exit:
    mbedtls_free(X);
    mbedtls_free(res);

    mbedtls_mpi_mod_modulus_free(&m);
    mbedtls_free(N);
}

static void test_ecp_mod_p_generic_raw_wrapper( void ** params )
{

    test_ecp_mod_p_generic_raw( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], (char *) params[2], (char *) params[3] );
}
#endif /* MBEDTLS_ECP_WITH_MPI_UINT */
#endif /* MBEDTLS_TEST_HOOKS */
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
#line 1678 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_mod_setup(char *input_A, int id, int ctype, int iret)
{
    int ret;
    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_modulus_init(&m);
    mbedtls_mpi_uint *p = NULL;
    size_t p_limbs;
    size_t bytes;

    TEST_EQUAL(mbedtls_test_read_mpi_core(&p, &p_limbs, input_A), 0);

    ret = mbedtls_ecp_modulus_setup(&m, id, ctype);
    TEST_EQUAL(ret, iret);

    if (ret == 0) {
        TEST_ASSERT(m.int_rep != MBEDTLS_MPI_MOD_REP_INVALID);
        /* Test for limb sizes */
        TEST_EQUAL(m.limbs, p_limbs);
        bytes = p_limbs * sizeof(mbedtls_mpi_uint);

        if (m.int_rep == MBEDTLS_MPI_MOD_REP_MONTGOMERY) {
            /* Test for validity of moduli by the presence of Montgomery consts */
            TEST_ASSERT(m.rep.mont.mm != 0);
            TEST_ASSERT(m.rep.mont.rr != NULL);
        } else {
            TEST_ASSERT(m.rep.ored.modp != NULL);
        }

        /* Compare output byte-by-byte */
        TEST_MEMORY_COMPARE(p, bytes, m.p, bytes);

        /* Test for user free-ing allocated memory */
        mbedtls_mpi_mod_modulus_free(&m);
    }

exit:
    mbedtls_mpi_mod_modulus_free(&m);
    mbedtls_free(p);
}

static void test_ecp_mod_setup_wrapper( void ** params )
{

    test_ecp_mod_setup( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_ECP_WITH_MPI_UINT */
#endif /* MBEDTLS_TEST_HOOKS */
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
#line 1720 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_mod_mul_inv(char *input_A, int id, int ctype)
{
    size_t limbs;
    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_residue rA; // For input
    mbedtls_mpi_mod_residue rA_inverse; // For inverse input
    mbedtls_mpi_mod_residue rX; // For result
    mbedtls_mpi_uint *rX_raw = NULL;
    mbedtls_mpi_uint *A_inverse = NULL;
    mbedtls_mpi_uint *A = NULL;
    mbedtls_mpi_uint *bufx = NULL;
    const mbedtls_mpi_uint one[1] = { 1 };

    mbedtls_mpi_mod_modulus_init(&m);

    TEST_ASSERT(mbedtls_ecp_modulus_setup(&m, id, ctype) == 0);

    TEST_EQUAL(mbedtls_test_read_mpi_core(&A, &limbs, input_A), 0);
    TEST_EQUAL(0, mbedtls_mpi_mod_residue_setup(&rA, &m, A, limbs));

    /* Test for limb sizes */
    TEST_EQUAL(m.limbs, limbs);

    TEST_CALLOC(A_inverse, limbs);
    TEST_EQUAL(0, mbedtls_mpi_mod_residue_setup(&rA_inverse, &m, A_inverse, limbs));

    TEST_CALLOC(rX_raw, limbs);
    TEST_EQUAL(0, mbedtls_mpi_mod_residue_setup(&rX, &m, rX_raw, limbs));

    /* Get inverse of A mode m, and multiply it with itself,
     * to see whether the result equal to '1' */
    TEST_EQUAL(0, mbedtls_mpi_mod_inv(&rA_inverse, &rA, &m));
    TEST_EQUAL(mbedtls_mpi_mod_mul(&rX, &rA, &rA_inverse, &m), 0);

    TEST_CALLOC(bufx, limbs);
    TEST_EQUAL(mbedtls_mpi_mod_write(&rX, &m, (unsigned char *) bufx,
                                     limbs * ciL,
                                     MBEDTLS_MPI_MOD_EXT_REP_LE), 0);

    TEST_MEMORY_COMPARE(bufx, ciL, one, ciL);
    /*Borrow the buffer of A to compare the left lims with 0 */
    memset(A, 0, limbs * ciL);
    TEST_MEMORY_COMPARE(&bufx[1], (limbs - 1) * ciL, A, (limbs - 1) * ciL);

exit:
    mbedtls_mpi_mod_modulus_free(&m);
    mbedtls_mpi_mod_residue_release(&rA);
    mbedtls_mpi_mod_residue_release(&rA_inverse);
    mbedtls_mpi_mod_residue_release(&rX);
    mbedtls_free(A);
    mbedtls_free(A_inverse);
    mbedtls_free(rX_raw);
    mbedtls_free(bufx);
}

static void test_ecp_mod_mul_inv_wrapper( void ** params )
{

    test_ecp_mod_mul_inv( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_ECP_WITH_MPI_UINT */
#endif /* MBEDTLS_TEST_HOOKS */
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
#line 1777 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_mod_add_sub(char *input_A, char *input_B, int id, int ctype)
{
    size_t p_A_limbs;
    size_t p_B_limbs;
    size_t bytes;
    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_residue rA;
    mbedtls_mpi_mod_residue rB;
    mbedtls_mpi_mod_residue rS;
    mbedtls_mpi_uint *p_A = NULL;
    mbedtls_mpi_uint *p_B = NULL;
    mbedtls_mpi_uint *p_S = NULL;

    mbedtls_mpi_mod_modulus_init(&m);

    TEST_EQUAL(mbedtls_test_read_mpi_core(&p_A, &p_A_limbs, input_A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi_core(&p_B, &p_B_limbs, input_B), 0);

    TEST_EQUAL(0, mbedtls_ecp_modulus_setup(&m, id, ctype));

    /* Test for limb sizes for two input value and modulus */
    TEST_EQUAL(p_A_limbs, p_B_limbs);
    TEST_EQUAL(m.limbs, p_A_limbs);
    bytes = p_A_limbs * ciL;

    TEST_CALLOC(p_S, p_A_limbs);

    TEST_EQUAL(mbedtls_mpi_mod_residue_setup(&rA, &m, p_A, p_A_limbs), 0);
    TEST_EQUAL(mbedtls_mpi_mod_residue_setup(&rB, &m, p_B, p_B_limbs), 0);
    TEST_EQUAL(mbedtls_mpi_mod_residue_setup(&rS, &m, p_S, p_A_limbs), 0);

    /* Firstly add A and B to get the sum S, then subtract B,
     * the difference should be equal to A*/
    TEST_EQUAL(0, mbedtls_mpi_mod_add(&rS, &rA, &rB, &m));
    TEST_EQUAL(0, mbedtls_mpi_mod_sub(&rS, &rS, &rB, &m));

    /* Compare difference with rA byte-by-byte */
    TEST_MEMORY_COMPARE(rA.p, bytes, rS.p, bytes);

exit:
    mbedtls_mpi_mod_modulus_free(&m);
    mbedtls_mpi_mod_residue_release(&rA);
    mbedtls_mpi_mod_residue_release(&rB);
    mbedtls_mpi_mod_residue_release(&rS);
    mbedtls_free(p_A);
    mbedtls_free(p_B);
    mbedtls_free(p_S);
}

static void test_ecp_mod_add_sub_wrapper( void ** params )
{

    test_ecp_mod_add_sub( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_ECP_WITH_MPI_UINT */
#endif /* MBEDTLS_TEST_HOOKS */
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
#line 1828 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_mod_read_write(char *input_A, int id, int ctype)
{
    size_t limbs;
    size_t bytes;
    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_residue rA; // For input
    mbedtls_mpi_mod_residue rX; // For read back
    mbedtls_mpi_uint *rX_raw = NULL;
    mbedtls_mpi_uint *A = NULL;
    mbedtls_mpi_uint *bufx = NULL;

    mbedtls_mpi_mod_modulus_init(&m);

    TEST_EQUAL(0, mbedtls_ecp_modulus_setup(&m, id, ctype));

    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&A, &limbs, input_A));
    TEST_EQUAL(0, mbedtls_mpi_mod_residue_setup(&rA, &m, A, limbs));

    /* Test for limb sizes */
    TEST_EQUAL(m.limbs, limbs);

    TEST_CALLOC(rX_raw, limbs);
    TEST_EQUAL(0, mbedtls_mpi_mod_residue_setup(&rX, &m, rX_raw, limbs));

    bytes = limbs * ciL;
    TEST_CALLOC(bufx, limbs);
    /* Write source mod residue to a buffer, then read it back to
     * the destination mod residue, compare the two mod residues.
     * Firstly test little endian write and read */
    TEST_EQUAL(0, mbedtls_mpi_mod_write(&rA, &m, (unsigned char *) bufx,
                                        bytes, MBEDTLS_MPI_MOD_EXT_REP_LE));

    TEST_EQUAL(0, mbedtls_mpi_mod_read(&rX, &m, (unsigned char *) bufx,
                                       bytes, MBEDTLS_MPI_MOD_EXT_REP_LE));

    TEST_EQUAL(limbs, rX.limbs);
    TEST_MEMORY_COMPARE(rA.p, bytes, rX.p, bytes);

    memset(bufx, 0x00, bytes);
    memset(rX_raw, 0x00, bytes);
    /* Then test big endian write and read */
    TEST_EQUAL(0, mbedtls_mpi_mod_write(&rA, &m, (unsigned char *) bufx,
                                        bytes,
                                        MBEDTLS_MPI_MOD_EXT_REP_BE));

    TEST_EQUAL(0, mbedtls_mpi_mod_read(&rX, &m, (unsigned char *) bufx,
                                       bytes,
                                       MBEDTLS_MPI_MOD_EXT_REP_BE));

    TEST_EQUAL(limbs, rX.limbs);
    TEST_MEMORY_COMPARE(rA.p, bytes, rX.p, bytes);

exit:
    mbedtls_mpi_mod_modulus_free(&m);
    mbedtls_mpi_mod_residue_release(&rA);
    mbedtls_mpi_mod_residue_release(&rX);
    mbedtls_free(A);
    mbedtls_free(rX_raw);
    mbedtls_free(bufx);
}

static void test_ecp_mod_read_write_wrapper( void ** params )
{

    test_ecp_mod_read_write( (char *) params[0], ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_ECP_WITH_MPI_UINT */
#endif /* MBEDTLS_TEST_HOOKS */
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
#line 1891 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_ecp_mod_random(int id, int ctype)
{
    size_t limbs;
    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_residue rX; // For random data
    mbedtls_mpi_uint *rX_raw = NULL;

    mbedtls_mpi_mod_modulus_init(&m);
    TEST_EQUAL(0, mbedtls_ecp_modulus_setup(&m, id, ctype));

    limbs = m.limbs;

    TEST_CALLOC(rX_raw, limbs);
    TEST_EQUAL(0, mbedtls_mpi_mod_residue_setup(&rX, &m, rX_raw, limbs));

    TEST_EQUAL(0, mbedtls_mpi_mod_random(&rX, 1, &m,
                                         mbedtls_test_rnd_std_rand, NULL));

    TEST_ASSERT(mbedtls_mpi_core_lt_ct(rX.p, m.p, limbs) == MBEDTLS_CT_TRUE);

exit:
    mbedtls_mpi_mod_modulus_free(&m);
    mbedtls_mpi_mod_residue_release(&rX);
    mbedtls_free(rX_raw);
}

static void test_ecp_mod_random_wrapper( void ** params )
{

    test_ecp_mod_random( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint );
}
#endif /* MBEDTLS_ECP_WITH_MPI_UINT */
#endif /* MBEDTLS_TEST_HOOKS */
#if defined(MBEDTLS_TEST_HOOKS)
#if defined(MBEDTLS_ECP_LIGHT)
#line 1919 "C:/Users/tomsk/OneDrive/Dokumente/Software/gnutls_mbedtls_unittest/mbedtls/tests/suites/test_suite_ecp.function"
static void test_check_variant(void)
{
    mbedtls_ecp_variant variant = mbedtls_ecp_get_variant();

#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
    TEST_EQUAL(variant, MBEDTLS_ECP_VARIANT_WITH_MPI_UINT);
#else
    TEST_EQUAL(variant, MBEDTLS_ECP_VARIANT_WITH_MPI_STRUCT);
#endif
exit:
    ;
}

static void test_check_variant_wrapper( void ** params )
{
    (void)params;

    test_check_variant(  );
}
#endif /* MBEDTLS_ECP_LIGHT */
#endif /* MBEDTLS_TEST_HOOKS */
#endif /* MBEDTLS_ECP_LIGHT */


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
    
#if defined(MBEDTLS_ECP_LIGHT)

        case 0:
            {
                *out_value = MBEDTLS_ECP_DP_SECP192K1;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_ECP_DP_SECP192R1;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ECP_DP_SECP224K1;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ECP_DP_SECP224R1;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ECP_DP_CURVE25519;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_ECP_DP_SECP256K1;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_ECP_DP_SECP256R1;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_ECP_DP_SECP384R1;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_ECP_DP_CURVE448;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_ECP_DP_SECP521R1;
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
    
#if defined(MBEDTLS_ECP_LIGHT)

        case 0:
            {
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_ECP_NIST_OPTIM)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_HAVE_INT32)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_HAVE_INT64)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 11:
            {
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 12:
            {
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
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

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_invalid_param_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_mbedtls_ecp_curve_info_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_check_pub_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_RESTARTABLE)
    test_ecp_test_vect_restart_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_RESTARTABLE) && defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    test_ecp_muladd_restart_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_ecp_test_vect_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_ecp_test_vec_x_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_ecp_test_mul_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_ecp_test_mul_rng_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED) && defined(MBEDTLS_ECP_C)
    test_ecp_muladd_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_fast_mod_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_write_binary_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_read_binary_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_mbedtls_ecp_tls_read_point_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_tls_write_read_point_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_mbedtls_ecp_tls_read_group_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_tls_write_read_group_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_mbedtls_ecp_group_metadata_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_mbedtls_ecp_check_privkey_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_check_pub_priv_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_ecp_calc_public_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_gen_keypair_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_ECP_C)
    test_mbedtls_ecp_gen_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 23 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_set_public_key_group_check_wrapper,
#else
    NULL,
#endif
/* Function Id: 24 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_set_public_key_good_wrapper,
#else
    NULL,
#endif
/* Function Id: 25 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_set_public_key_after_private_wrapper,
#else
    NULL,
#endif
/* Function Id: 26 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_mbedtls_ecp_read_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 27 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_DEPRECATED)
    test_ecp_write_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 28 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_write_key_ext_wrapper,
#else
    NULL,
#endif
/* Function Id: 29 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_MONTGOMERY_ENABLED) && defined(MBEDTLS_ECP_LIGHT)
    test_genkey_mx_known_answer_wrapper,
#else
    NULL,
#endif
/* Function Id: 30 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_set_zero_wrapper,
#else
    NULL,
#endif
/* Function Id: 31 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_SELF_TEST)
    test_ecp_selftest_wrapper,
#else
    NULL,
#endif
/* Function Id: 32 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_export_wrapper,
#else
    NULL,
#endif
/* Function Id: 33 */

#if defined(MBEDTLS_ECP_LIGHT)
    test_ecp_check_order_wrapper,
#else
    NULL,
#endif
/* Function Id: 34 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_WITH_MPI_UINT)
    test_ecp_mod_p_generic_raw_wrapper,
#else
    NULL,
#endif
/* Function Id: 35 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_WITH_MPI_UINT)
    test_ecp_mod_setup_wrapper,
#else
    NULL,
#endif
/* Function Id: 36 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_WITH_MPI_UINT)
    test_ecp_mod_mul_inv_wrapper,
#else
    NULL,
#endif
/* Function Id: 37 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_WITH_MPI_UINT)
    test_ecp_mod_add_sub_wrapper,
#else
    NULL,
#endif
/* Function Id: 38 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_WITH_MPI_UINT)
    test_ecp_mod_read_write_wrapper,
#else
    NULL,
#endif
/* Function Id: 39 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_WITH_MPI_UINT)
    test_ecp_mod_random_wrapper,
#else
    NULL,
#endif
/* Function Id: 40 */

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_LIGHT)
    test_check_variant_wrapper,
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
    const char *default_filename = ".\\test_suite_ecp.generated.datax";
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
