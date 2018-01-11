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

START_TEST(test_chkpke_export_der)
    CHKPKE_t pke;
    int i;
    int sz;
    unsigned char *der;

    CHKPKE_init_Gen(pke, 512, 400, 6, 16);

    der = (unsigned char *)CHKPKE_pubkey_encode_DER(pke, 10, &sz);
    printf("DER encoded pubkey (%d bytes)=\n", sz);
    for (i = 0; i < sz; i++) {
        printf("%02X", der[i]);
    }
    printf("\n");

    CHKPKE_clear(pke);
END_TEST

static Suite *CHKPKE_test_suite(void) {
    Suite *s;
    TCase *tc;
    
    s = suite_create("Forward Secure PKE implementation based on CHK Model");
    tc = tcase_create("allocation and traversal");

    tcase_add_test(tc, test_chkpke_init);
    tcase_add_test(tc, test_chkpke_export_der);
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
