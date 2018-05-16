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
#include <field.h>
#include <gmp.h>
#include <math.h>
#include <mpzurandom.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>

//static char pCurve25519[] = "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
static char pCurve41417[] = "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef";

START_TEST(test_cwh)
    int i, j, coll;
    mpz_t p, q, a, b, x, hx, y, hy;
    cwHash_t cwh;
    mpz_init(p);
    mpz_init(q);
    mpz_init(a);
    mpz_init(b);
    mpz_init(x);
    mpz_init(hx);
    mpz_init(y);
    mpz_init(hy);

    mpz_set_ui(p, 251);
    mpz_set_ui(q, 31);
    mpz_urandom(a, p);
    mpz_urandom(b, p);

    cwHash_init(cwh, p);

    cwHash_set_mpz(cwh, q, p, a, b);
    
    for (j = 0; j < 251; j++) {
        coll = 0;
        mpz_set_ui(y, j);
        cwHash_hashval(hy, cwh, y);
        assert(mpz_cmp_ui(hy, 0) >= 0);
        assert(mpz_cmp(hy, q) <0);
        //gmp_printf("cw-H(%ZX) = %ZX : ", y, hy);
        for (i = 0; i < 251; i++) {
            mpz_set_ui(x, i);
            cwHash_hashval(hx, cwh, x);
            if(mpz_cmp(hx, hy) == 0) {
                coll += 1;
                //gmp_printf("%ZX ", x);
            }
            assert(mpz_cmp_ui(hx, 0) >= 0);
            assert(mpz_cmp(hx, q) <0);
        }
        //printf("\n");
        // ensure uniformity - expected collisions = 251/31 = 8.09
        // if >9 or <8 we have a problem
        assert((coll > 7) && (coll <10));
    }

    // 2**414-17, 2**255-19 (prime numbers)
    mpz_set_str(p, pCurve41417, 0);
    mpz_set_ui(q, 251);
    mpz_urandom(a, p);
    mpz_urandom(b, p);
    cwHash_set_mpz(cwh, q, p, a, b);
    
    for (j = 0; j < 100; j++) {
        coll = 0;
        mpz_urandom(y, p);
        cwHash_hashval(hy, cwh, y);
        assert(mpz_cmp_ui(hy, 0) >= 0);
        assert(mpz_cmp(hy, q) <0);
        //gmp_printf("cw-H(%ZX) = %ZX : ", y, hy);
        for (i = 0; i < 1000; i++) {
            mpz_urandom(x, p);
            cwHash_hashval(hx, cwh, x);
            if(mpz_cmp(hx, hy) == 0) {
                coll += 1;
                //gmp_printf("%ZX ", x);
            }
            assert(mpz_cmp_ui(hx, 0) >= 0);
            assert(mpz_cmp(hx, q) <0);
        }
        //printf("\n");
    }
    
    cwHash_clear(cwh);
    mpz_clear(hy);
    mpz_clear(y);
    mpz_clear(hx);
    mpz_clear(x);
    mpz_clear(b);
    mpz_clear(a);
    mpz_clear(q);
    mpz_clear(p);
END_TEST

START_TEST(test_cwh_urandom)
    int i, j, p, coll;
    mpz_t q, x, hx, y, hy;
    cwHash_t cwh;
    mpz_init(q);
    mpz_init(x);
    mpz_init(hx);
    mpz_init(y);
    mpz_init(hy);

    mpz_set_ui(q, 31);
    cwHash_init(cwh, q);
    cwHash_urandom(cwh, q);
    p = mpz_get_ui(cwh->p);
    //printf("p = %d\n", p);
    
    for (j = 0; j < p ; j++) {
        coll = 0;
        mpz_set_ui(y, j);
        cwHash_hashval(hy, cwh, y);
        assert(mpz_cmp_ui(hy, 0) >= 0);
        assert(mpz_cmp(hy, q) <0);
        //gmp_printf("cw-H(%ZX) = %ZX : ", y, hy);
        for (i = 0; i < p ; i++) {
            mpz_set_ui(x, i);
            cwHash_hashval(hx, cwh, x);
            if(mpz_cmp(hx, hy) == 0) {
                coll += 1;
                //gmp_printf("%ZX ", x);
            }
            assert(mpz_cmp_ui(hx, 0) >= 0);
            assert(mpz_cmp(hx, q) <0);
        }
        //printf("j = %d, coll = %d\n", j, coll);
        assert((coll >= (p/31)) && (coll <= ((p/31)+1)));
    }

    cwHash_clear(cwh);
    mpz_clear(hy);
    mpz_clear(y);
    mpz_clear(hx);
    mpz_clear(x);
    mpz_clear(q);
END_TEST

START_TEST(test_cwh_set)
    int j;
    mpz_t p, q, a, b, x, hx, y, hy;
    cwHash_t cwh, cwh_cp;
    mpz_init(p);
    mpz_init(q);
    mpz_init(a);
    mpz_init(b);
    mpz_init(x);
    mpz_init(hx);
    mpz_init(y);
    mpz_init(hy);

    mpz_set_ui(p, 251);
    mpz_set_ui(q, 31);
    mpz_urandom(a, p);
    mpz_urandom(b, p);
    cwHash_init(cwh, p);
    cwHash_init(cwh_cp, p);
    cwHash_set_mpz(cwh, q, p, a, b);
    cwHash_set(cwh_cp, cwh);
    
    for (j = 0; j < 251; j++) {
        mpz_set_ui(y, j);
        cwHash_hashval(hy, cwh, y);
        mpz_set(x, y);
        cwHash_hashval(hx, cwh_cp, x);
        assert(mpz_cmp(hx, hy) == 0);
    }

    // 2**414-17, 2**255-19 (prime numbers)
    mpz_set_str(p, pCurve41417, 0);
    mpz_set_ui(q, 251);
    mpz_urandom(a, p);
    mpz_urandom(b, p);
    cwHash_set_mpz(cwh, q, p, a, b);
    cwHash_set(cwh_cp, cwh);
    
    for (j = 0; j < 100; j++) {
        mpz_urandom(y, p);
        cwHash_hashval(hy, cwh, y);
        mpz_set(x, y);
        cwHash_hashval(hx, cwh_cp, x);
        assert(mpz_cmp(hx, hy) == 0);
    }
    
    cwHash_clear(cwh_cp);
    cwHash_clear(cwh);
    mpz_clear(hy);
    mpz_clear(y);
    mpz_clear(hx);
    mpz_clear(x);
    mpz_clear(b);
    mpz_clear(a);
    mpz_clear(q);
    mpz_clear(p);
END_TEST

static Suite *cwHash_test_suite(void) {
    Suite *s;
    TCase *tc;
    
    s = suite_create("Carter-Wegman Universal Hash Family");
    tc = tcase_create("arithmetic");

    tcase_add_test(tc, test_cwh);
    tcase_add_test(tc, test_cwh_urandom);
    tcase_add_test(tc, test_cwh_set);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = cwHash_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
