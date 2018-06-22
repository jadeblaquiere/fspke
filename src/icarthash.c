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
#include <ecc.h>
#include <fspke/cwhash.h>
#include <fspke/icarthash.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>

void icartHash_init(icartHash_t ih, mpECurve_t cv) {
    mpECurve_init(ih->cv);
    mpECurve_set(ih->cv, cv);
    cwHash_init(ih->cwa, cv->n);
    cwHash_init(ih->cwb, cv->n);
    mpECP_init(ih->pt, ih->cv);
    mpFp_init_fp(ih->precalc1_3, cv->fp);
    mpFp_init_fp(ih->precalc1_27, cv->fp);
    mpz_init(ih->precalc_cubert);
    return;
}

void icartHash_clear(icartHash_t ih) {
    mpECurve_clear(ih->cv);
    cwHash_clear(ih->cwa);
    cwHash_clear(ih->cwb);
    mpECP_clear(ih->pt);
    mpFp_clear(ih->precalc1_3);
    mpFp_clear(ih->precalc1_27);
    mpz_clear(ih->precalc_cubert);
#ifdef  SAFE_CLEAN
    memset((void *)(ih), 0, sizeof(*ih));
#endif
    return;
}

static void _icartHash_precalc(icartHash_t rih) {
    mpz_t t;
    mpFp_t s;
    mpz_init(t);
    mpz_mod_ui(t, rih->cv->fp->p, 3);
    // cube root by exponentiation assumes p = 2 mod 3
    assert(mpz_get_ui(t) == 2);
    // 3**(-1) mod p 
    mpFp_set_ui_fp(rih->precalc1_3, 3, rih->cv->fp);
    mpFp_inv(rih->precalc1_3, rih->precalc1_3);
    // 27**(-1) mod p
    mpFp_set_ui_fp(rih->precalc1_27, 27, rih->cv->fp);
    mpFp_inv(rih->precalc1_27, rih->precalc1_27);
    // 3**(-1) mod (p-1) -> see https://en.wikipedia.org/wiki/Cubic_reciprocity
    mpz_sub_ui(t, rih->cv->fp->p, 1);
    mpFp_init(s, t);
    mpFp_set_ui(s, 3, t);
    mpFp_inv(s, s);
    mpz_set_mpFp(t, s);
    mpz_set(rih->precalc_cubert, t);
    mpFp_clear(s);
    mpz_clear(t);
}

void icartHash_set(icartHash_t rih, icartHash_t ih) {
    mpECurve_set(rih->cv, ih->cv);
    cwHash_set(rih->cwa, ih->cwa);
    cwHash_set(rih->cwb, ih->cwb);
    mpECP_set(rih->pt, ih->pt);
    mpECP_scalar_base_mul_setup(rih->pt);
    _icartHash_precalc(rih);
    return;
}

void icartHash_set_param(icartHash_t rih, mpECurve_t cv, cwHash_t cwha, cwHash_t cwhb) {
    assert(cv->type == EQTypeShortWeierstrass);
    assert(mpz_cmp(cwha->q, cv->n) == 0);
    assert(mpz_cmp(cwhb->q, cv->n) == 0);
    mpECurve_set(rih->cv, cv);
    cwHash_set(rih->cwa, cwha);
    cwHash_set(rih->cwb, cwhb);
    assert(mpECurve_point_check(cv, cv->G[0], cv->G[1]));
    mpECP_set_mpz(rih->pt, cv->G[0], cv->G[1], rih->cv);
    mpECP_scalar_base_mul_setup(rih->pt);
    _icartHash_precalc(rih);
    return;
}

void icartHash_urandom(icartHash_t rih, mpECurve_t cv) {
    cwHash_t a, b;
    cwHash_init(a, cv->n);
    cwHash_init(b, cv->n);
    cwHash_urandom(a, cv->n);
    cwHash_urandom(b, cv->n);
    icartHash_set_param(rih, cv, a, b);
    cwHash_clear(b);
    cwHash_clear(a);
    return;
}

// original method proposed by https://eprint.iacr.org/2009/226.pdf

static void _icartHash_deterministic_map(mpECP_t hx, icartHash_t ih, mpz_t x) {
    mpFp_t u, v, s, t;
    mpFp_init_fp(u, ih->cv->fp);
    mpFp_init_fp(v, ih->cv->fp);
    mpFp_init_fp(s, ih->cv->fp);
    mpFp_init_fp(t, ih->cv->fp);
    // v = (3*a - u**4) / (6*u)
    mpFp_set_mpz(u, x, ih->cv->fp->p);
    mpFp_mul_ui(v, ih->cv->coeff.ws.a, 3);
    mpFp_pow_ui(t, u, 4);
    mpFp_sub(v, v, t);
    mpFp_mul_ui(t, u, 6);
    mpFp_inv(t, t);
    mpFp_mul(v, v, t);
    // x = (v**2 - b - u**6/27)**(1/3) + (u**2/3)
    mpFp_mul(s, v, v);
    mpFp_set(t, ih->cv->coeff.ws.b);
    mpFp_sub(s, s, t);
    mpFp_pow_ui(t, u, 6);
    mpFp_mul(t, t, ih->precalc1_27);
    mpFp_sub(s, s, t);
    mpFp_pow_mpz(t, s, ih->precalc_cubert);
    mpFp_mul(s, u, u);
    mpFp_mul(s, s, ih->precalc1_3);
    mpFp_add(t, t, s);
    // y = u * x + v
    mpFp_mul(s, u, t);
    mpFp_add(s, s, v);
    assert(mpECurve_point_check(ih->cv, t->i, s->i));
    mpECP_set_mpz(hx, t->i, s->i, ih->cv);
    mpFp_clear(t);
    mpFp_clear(s);
    mpFp_clear(v);
    mpFp_clear(u);
}

// uniform mapping proposed by https://eprint.iacr.org/2009/340.pdf
// (when added to deterministic mapping, result is uniform)

static void _icartHash_uniform_map(mpECP_t hx, icartHash_t ih, mpz_t x) {
    // uniform map is simply scalar multiplication
    mpECP_scalar_base_mul_mpz(hx, ih->pt, x);
    return;
}

void icartHash_hashval(mpECP_t hash, icartHash_t ih, mpz_t x) {
    mpz_t ha, hb;
    mpECP_t pa, pb;
    mpz_init(ha);
    mpz_init(hb);
    mpECP_init(pa, ih->cv);
    mpECP_init(pb, ih->cv);
    // composition of functions: H = D(Ha(x)) + U(Hb(x))
    // Ha, Hb independent {0,1}N -> Fp mappings
    // D, U are Fp -> E(Fp) mappings
    cwHash_hashval(ha, ih->cwa, x);
    cwHash_hashval(hb, ih->cwb, x);
    _icartHash_deterministic_map(pa, ih, ha);
    _icartHash_uniform_map(pb, ih, hb);
#if 0
    // validate result point is valid
    mpz_set_mpECP_affine_x(ha, pa);
    mpz_set_mpECP_affine_y(hb, pa);
    if (!pa->is_neutral) {
        assert(mpECurve_point_check(ih->cv, ha, hb));
    }
    mpz_set_mpECP_affine_x(ha, pb);
    mpz_set_mpECP_affine_y(hb, pb);
    if (!pb->is_neutral) {
        assert(mpECurve_point_check(ih->cv, ha, hb));
    }
#endif
    mpECP_add(hash, pa, pb);
    mpECP_clear(pb);
    mpECP_clear(pa);
    mpz_clear(hb);
    mpz_clear(ha);
    return;
}
