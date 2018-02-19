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
#include <mpzurandom.h>

// primality test will accept a composite with probability 4**(-reps)
#define _MILLER_RABIN_REPS    (40)

void cwHash_init(cwHash_t cwh) {
    mpz_init(cwh->p);
    mpz_init(cwh->q);
    mpFp_init(cwh->a);
    mpFp_init(cwh->b);
    return;
}

void cwHash_clear(cwHash_t cwh) {
    mpz_clear(cwh->p);
    mpz_clear(cwh->q);
    mpFp_clear(cwh->a);
    mpFp_clear(cwh->b);
    return;
}

void cwHash_set(cwHash_t rcwh, cwHash_t cwh) {
    assert(mpz_cmp(cwh->p, cwh->q) > 0);
    mpz_set(rcwh->p, cwh->p);
    mpz_set(rcwh->q, cwh->q);
    mpFp_set(rcwh->a, cwh->a);
    mpFp_set(rcwh->b, cwh->b);
    return;
}

void cwHash_set_mpz(cwHash_t cwh, mpz_t q, mpz_t p, mpz_t a, mpz_t b) {
    assert(mpz_cmp(p, q) > 0);
    mpz_set(cwh->p, p);
    mpz_set(cwh->q, q);
    mpFp_set_mpz(cwh->a, a, p);
    mpFp_set_mpz(cwh->b, b, p);
    return;
}

void cwHash_urandom(cwHash_t cwh, mpz_t q) {
    mpz_t qq, p;
    mpz_init(qq);
    mpz_init(p);
    
    mpz_mul(qq, q, q);
    do {
        mpz_urandom(p, qq);
    } while ((mpz_cmp(p, q) <= 0) || (mpz_probab_prime_p(p, _MILLER_RABIN_REPS) == 0));

    mpz_set(cwh->q, q);
    mpz_set(cwh->p, p);
    mpFp_urandom(cwh->a, p);
    mpFp_urandom(cwh->b, p);

    mpz_clear(p);
    mpz_clear(qq);
}

void cwHash_hashval(mpz_t hash, cwHash_t cwh, mpz_t x) {
    mpFp_t xf;
    mpz_t y;
    mpFp_init(xf);
    mpz_init(y);
    mpFp_set_mpz(xf, x, cwh->p);
    mpFp_mul(xf, xf, cwh->a);
    mpFp_add(xf, xf, cwh->b);
    mpz_set_mpFp(y, xf);
    mpz_mod(y, y, cwh->q);
    mpz_set(hash, y);
    mpz_clear(y);
    mpFp_clear(xf);
    return;
}
