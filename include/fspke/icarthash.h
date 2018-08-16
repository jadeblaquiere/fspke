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

#ifndef _ICARTHASH_H_INCLUDED_
#define _ICARTHASH_H_INCLUDED_

#include <ecc.h>
#include <fspke/cwhash.h>
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

// icartHash uses the method proposed by Thomas Icart(1) and extended by
// Eric Brier et. al.(2) to hash a N-bit integer value into to a elliptic
// curve group defined over a finite field, E(Fp), where 2**N > q and E is
// in the Short Weierstrass for y**2 = x**3 + ax + b with Generator G and
// order n.
// (1) : Thomas Icart, "How to Hash into Elliptic Curves", CRYPTO2009, 
// https://eprint.iacr.org/2009/226.pdf
// (2) : Eric Brier et. al., "Efficient Indifferentiable Hashing into
// Ordinary Elliptic Curves", CRYPTO2010, https://eprint.iacr.org/2009/340.pdf

typedef struct {
    mpECurve_t cv;
    cwHash_t cwa;
    cwHash_t cwb;
    mpECP_t pt;
    mpFp_t precalc1_3;
    mpFp_t precalc1_27;
    mpz_t precalc_cubert;
} _icartHash_t;

typedef _icartHash_t icartHash_t[1];
typedef _icartHash_t *icartHash_ptr;

void icartHash_init(icartHash_t ih, mpECurve_t cv);
void icartHash_clear(icartHash_t ih);

void icartHash_set(icartHash_t rih, icartHash_t ih);
void icartHash_set_param(icartHash_t rih, mpECurve_t cv, cwHash_t cwha, cwHash_t cwhb);

void icartHash_urandom(icartHash_t rih, mpECurve_t cv);

void icartHash_hashval(mpECP_t hash, icartHash_t ih, mpz_t x);

#ifdef __cplusplus
}
#endif

#endif // _ICARTHASH_H_INCLUDED_
