//BSD 3-Clause License
//
//Copyright (c) 2017, jadeblaquiere
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
#include <check.h>
#include <chkpke.h>
#include <stdio.h>
#include <stdlib.h>

static FILE *_f_dev_urandom = NULL;

static int randint(int min, int max) {
    unsigned int range, value;
    assert(max > min);

    // +1 makes this return values from min to max inclusive
    range = (max - min) + 1;
    if (_f_dev_urandom == NULL) {
        _f_dev_urandom = fopen("/dev/urandom", "rb");
        assert(_f_dev_urandom != NULL);
    }
    assert(fread(&value, sizeof(int), 1, _f_dev_urandom) == 1);
    value = value % range;
    assert(value < range);
    return min + (value % range);
}

START_TEST(test_chkpke_init)
    CHKPKE_t pke;
    
    CHKPKE_init_Gen(pke, 512, 384, 4, 8);
    CHKPKE_clear(pke);
    CHKPKE_init_Gen(pke, 256, 192, 4, 8);
    CHKPKE_clear(pke);
    CHKPKE_init_Gen(pke, 128, 96, 4, 8);
    CHKPKE_clear(pke);
    CHKPKE_init_Gen(pke, 64, 48, 4, 8);
    CHKPKE_clear(pke);
END_TEST

START_TEST(test_chkpke_der)
    CHKPKE_t pke;
    int i;

    CHKPKE_init_Gen(pke, 512, 400, 6, 16);

    for (i = 0; i < 50; i++) {
        CHKPKE_Der(pke, randint(0, (1<<(6*4-1))));
        //printf("found\n");
    }

    CHKPKE_clear(pke);
END_TEST

START_TEST(test_chkpke_export_pubkey_der)
    CHKPKE_t pke;
    CHKPKE_t npke;
    int i;
    int sz1;
    int sz2;
    unsigned char *der1;
    unsigned char *der2;

    CHKPKE_init_Gen(pke, 512, 400, 6, 16);

    der1 = (unsigned char *)CHKPKE_pubkey_encode_DER(pke, &sz1);
    assert(der1 != NULL);
    printf("DER encoded pubkey (%d bytes)=\n", sz1);
    for (i = 0; i < sz1; i++) {
        printf("%02X", der1[i]);
    }
    printf("\n");

    i = CHKPKE_init_pubkey_decode_DER(npke, (char *)der1, sz1);
    assert(i == 0);

    der2 = (unsigned char *)CHKPKE_pubkey_encode_DER(npke, &sz2);
    assert(der2 != NULL);
    printf("DER encoded pubkey (%d bytes)=\n", sz2);
    assert(sz1 == sz2);
    for (i = 0; i < sz2; i++) {
        printf("%02X", der2[i]);
        assert(der1[i] == der2[i]);
    }
    printf("\n");

    free(der2);
    free(der1);
    CHKPKE_clear(pke);
END_TEST

START_TEST(test_chkpke_export_privkey_der)
    CHKPKE_t pke;
    //int i;
    int sz;
    unsigned char *der;

    CHKPKE_init_Gen(pke, 512, 400, 6, 16);

    der = (unsigned char *)CHKPKE_privkey_encode_DER(pke, randint(0, (1<<(6*4-1))), &sz);
    assert(der != NULL);
    //printf("DER encoded privkey (%d bytes)=\n", sz);
    //for (i = 0; i < sz; i++) {
    //    printf("%02X", der[i]);
    //}
    //printf("\n");

    free(der);
    CHKPKE_clear(pke);
END_TEST

static Suite *CHKPKE_test_suite(void) {
    Suite *s;
    TCase *tc;
    
    s = suite_create("Forward Secure PKE implementation based on CHK Model");
    tc = tcase_create("allocation and traversal");

    tcase_add_test(tc, test_chkpke_init);
    tcase_add_test(tc, test_chkpke_der);
    tcase_add_test(tc, test_chkpke_export_pubkey_der);
    tcase_add_test(tc, test_chkpke_export_privkey_der);

    // set 10 second timeout instead of default 4
    tcase_set_timeout(tc, 10.0);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = CHKPKE_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
