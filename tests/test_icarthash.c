//BSD 3-Clause License
//
//Copyright (c) 2018, jadeblaquiere
//All rights reserved.
//
//Redistribution and use in source and binary forms, with or without
//modification, are permitted provided that the following conditions are met:
//
//* Redistributions of source code must retain the above copyright notice, this
//  list of conditions and the following disclaimer.
//
//* Redistributions in binary form must reproduce the above copyright notice,
//  this list of conditions and the following disclaimer in the documentation
//  and/or other materials provided with the distribution.
//
//* Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <assert.h>
#include <cwhash.h>
#include <ecurve.h>
#include <field.h>
#include <gmp.h>
#include <icarthash.h>
#include <math.h>
#include <mpzurandom.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    _mpECurve_eq_type type;
    char *name;
    char *p;
    char *a;
    char *b;
    char *n;
    char *h;
    char *Gx;
    char *Gy;
    int bits;
} _std_ws_curve_t;

_std_ws_curve_t test_curve[] = {
    {
        EQTypeShortWeierstrass,
        "t0",
        "743",
        "1",
        "0",
        "31",
        "24",
        "0x02B",
        "0x2E0",
        10
    },
    {
        EQTypeShortWeierstrass,
        "t1",
        "5090635295044090796479352375020271908250739742722034086194548603262062411024607006170934645620063877713096979752019604322958034081040130730929574563818223",
        "1",
        "0",
        "1291124939043454294827959586001505937164852896414611756415329678270323811008420598675952144323822769571450015713446592511",
        "3942790617006863973652222529754384",
        "0x1A2FB9DDF936098B41FF04F91B6CE2B958412F25A9CC22CD39FDB7EC9B34C653B948FBDD69CF26394CF36CCFEB5B16528752C7DB00075B98392BF51D13648271",
        "0x2EDC0D64EC9226C75BF2F9500FD7DFBDC3A89F69EEA4DD279906D4F876B659800C82A03E7F8F96D6E5A805D9CA37171DE15D3AAE8A9274464C390E5EE6E50449",
        511
    }
};


START_TEST(test_ih_urandom)
    int i, j, slen, ncurves;
    char *buffer;
    mpz_t a, b, x, y;
    mpECP_t A;
    mpECP_t B;
    mpECurve_t cv;
    icartHash_t ih;
    icartHash_t ih_cp;
    mpz_init(a);
    mpz_init(b);
    mpz_init(x);
    mpz_init(y);
    mpECurve_init(cv);
    
    ncurves = sizeof(test_curve)/sizeof(test_curve[0]);
    for (i = 0; i < ncurves; i++) {
        mpECurve_set_str_ws(cv, test_curve[i].p, test_curve[i].a, test_curve[i].b, test_curve[i].n, test_curve[i].h, test_curve[i].Gx, test_curve[i].Gy, test_curve[i].bits);
        mpECP_init(A, cv);
        mpECP_init(B, cv);
        icartHash_init(ih, cv);
        icartHash_init(ih_cp, cv);
        icartHash_urandom(ih, cv);
        icartHash_set(ih_cp, ih);
        for (j = 0; j < 100; j++) {
            mpz_urandom(a, cv->n);
            mpz_set(b, a);
            icartHash_hashval(A, ih, a);
            icartHash_hashval(B, ih_cp, b);
            assert(mpz_cmp(a, b) == 0);
            assert(mpECP_cmp(A, B) == 0);
            mpz_set_mpECP_affine_x(x, A);
            mpz_set_mpECP_affine_y(y, A);
            slen = mpECP_out_strlen(A, 0);
            buffer = malloc((slen + 1)* sizeof(char));
            assert(buffer != NULL);
            mpECP_out_str(buffer, A, 0);
            gmp_printf("Rand :   %ZX\n", a);
            printf("Hash : %s\n\n", buffer);
            assert(strlen(buffer) == slen);
            if (!A->is_neutral) assert(mpECurve_point_check(cv, x, y));
            free(buffer);
        }
        icartHash_clear(ih_cp);
        icartHash_clear(ih);
        mpECP_clear(B);
        mpECP_clear(A);
    }

    mpECurve_clear(cv);
    mpz_clear(y);
    mpz_clear(x);
    mpz_clear(b);
    mpz_clear(a);
END_TEST

START_TEST(test_ih_first20)
    int i, j, slen, ncurves;
    char *buffer;
    mpz_t a, b, x, y;
    mpECP_t A;
    mpECP_t B;
    mpECurve_t cv;
    icartHash_t ih;
    icartHash_t ih_cp;
    mpz_init(a);
    mpz_init(b);
    mpz_init(x);
    mpz_init(y);
    mpECurve_init(cv);

    ncurves = sizeof(test_curve)/sizeof(test_curve[0]);
    for (i = 0; i < ncurves; i++) {
        mpECurve_set_str_ws(cv, test_curve[i].p, test_curve[i].a, test_curve[i].b, test_curve[i].n, test_curve[i].h, test_curve[i].Gx, test_curve[i].Gy, test_curve[i].bits);
        mpECP_init(A, cv);
        mpECP_init(B, cv);
        icartHash_init(ih, cv);
        icartHash_init(ih_cp, cv);
        icartHash_urandom(ih, cv);
        icartHash_set(ih_cp, ih);
        for (j = 0; j < 20; j++) {
            mpz_set_ui(a, j);
            mpz_set(b, a);
            icartHash_hashval(A, ih, a);
            icartHash_hashval(B, ih_cp, b);
            assert(mpz_cmp(a, b) == 0);
            assert(mpECP_cmp(A, B) == 0);
            mpz_set_mpECP_affine_x(x, A);
            mpz_set_mpECP_affine_y(y, A);
            slen = mpECP_out_strlen(A, 0);
            buffer = malloc((slen + 1)* sizeof(char));
            assert(buffer != NULL);
            mpECP_out_str(buffer, A, 0);
            gmp_printf("A :   %ZX\n", a);
            printf("Hash : %s\n\n", buffer);
            assert(strlen(buffer) == slen);
            if (!A->is_neutral) assert(mpECurve_point_check(cv, x, y));
            free(buffer);
        }
        icartHash_clear(ih_cp);
        icartHash_clear(ih);
        mpECP_clear(B);
        mpECP_clear(A);
    }

    mpECurve_clear(cv);
    mpz_clear(y);
    mpz_clear(x);
    mpz_clear(b);
    mpz_clear(a);
END_TEST

static Suite *iHash_test_suite(void) {
    Suite *s;
    TCase *tc;
    
    s = suite_create("Icart {0,1}N->E(Fp) Universal Hash Family");
    tc = tcase_create("arithmetic");
    // set 10 second timeout instead of default 4
    tcase_set_timeout(tc, 20.0);

    tcase_add_test(tc, test_ih_urandom);
    tcase_add_test(tc, test_ih_first20);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = iHash_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
