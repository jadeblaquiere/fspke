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

#ifndef _CWHASH_H_INCLUDED_
#define _CWHASH_H_INCLUDED_

#include <field.h>
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

// cwHash implements the Carter and Wegman universal hash function family
// to map (hash) an integer value of arbitrary size to a member of the
// the integers less than q : {0,1}N -> {0, 1, ... , q-2, q-1}.
// p must be a prime and for the distribution to be uniform p is much greater
// than q : p >> q.
// 
// see: https://en.wikipedia.org/wiki/Universal_hashing

typedef struct {
    mpz_t p;
    mpz_t q;
    mpFp_t a;
    mpFp_t b;
} _cwHash_t;

typedef _cwHash_t cwHash_t[1];

void cwHash_init(cwHash_t cwh, mpz_t p);
void cwHash_clear(cwHash_t cwh);

void cwHash_set(cwHash_t rcwh, cwHash_t cwh);

void cwHash_set_mpz(cwHash_t cwh, mpz_t q, mpz_t p, mpz_t a, mpz_t b);

void cwHash_urandom(cwHash_t cwh, mpz_t q);

void cwHash_hashval(mpz_t hash, cwHash_t cwh, mpz_t x);

#ifdef __cplusplus
}
#endif

#endif // _CWHASH_H_INCLUDED_
