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

#ifndef _CHKPKE_H_INCLUDED_
#define _CHKPKE_H_INCLUDED_

#include <ecurve.h>
#include <field.h>
#include <gmp.h>
#include <icarthash.h>
#include <pbc.h>
#include <sparsetree.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// chkpke implements a cryptosystem based on the Canetti, Halevi and Katz
// model as defined in "A Forward-Secure Public-Key Encryption Scheme",
// published in Eurocrypt2003, archived (https://eprint.iacr.org/2003/083).
// This asymmetric encryption model enables encryption of data based on a
// static public key and a defined set of intervals. The private key has
// the ability to evolve over time to "forget" the ability to decrypt
// messages from previous intervals (forward security) such that messages
// from previous intervals cannot be decrypted if the revised (pruned) public
// key is divulged.

// The Canetti-Halevi-Katz scheme uses symmetric pairings of Elliptic
// Curves (ECs), G1 X G1 -> G2, where elements in G1 are EC points and
// elements in G2 are curve points in Fp2 (F-p-squared). Messages (M) are
// in Fp2. Ciphertexts include multiple EC points and an element in Fp2.
// The Public Key includes parameters of the curves, pairing and a universal
// hash function.

// NOTE: This implementation forgoes the optimization (see Section 3.3) of
// using every node of the tree and instead only uses leaf nodes such that
// a constant ciphertext size is maintained. This optimization does not
// affect the security proofs provided by Canetti, Halevi and Katz and with
// larger btree orders the cost in storage is negligible.

typedef struct {
    bool is_secret;
    int depth;
    int order;
    pbc_param_t param;
    pairing_t pairing;
    element_t P;
    element_t Q;
    element_t ePQ;
    mpECurve_t C;
    icartHash_t H;
    sparseTree_t tree;
    element_t eQH;
    mpz_t q;
    mpz_t r;
    mpz_t h;
    int p_exp2;
    int p_exp1;
    int p_sign1;
    int p_sign0;
} _CHKPKE_t;

typedef _CHKPKE_t CHKPKE_t[1];

//void CHKPKE_init(chkPKE_t chk);
void CHKPKE_clear(CHKPKE_t chk);

// Gen initializes the pairing-based cryptosystem and creates a private key
// The Gen initialization process uses a cryptographically secure random to
// create a new public and private key set
void CHKPKE_init_Gen(CHKPKE_t chk, int qbits, int rbits, int depth, int order);

// For import/export use ASN1 Distinguished Encoding Rules (DER) format
// to represent the structured key as an string of bytes.
// encode_DER allocates and returns a char type string - the caller must
// use free() to release that memory once no longer in use.
char *CHKPKE_pubkey_encode_DER(CHKPKE_t chk, int *sz);
char *CHKPKE_privkey_encode_DER(CHKPKE_t chk, int64_t interval, int *sz);

// Der attempts to derive the key material for a specific interval and returns
// -1 on failure (which will occur when attempting to derive a key for a past
// interval when the key has been pruned).
int CHKPKE_Der(CHKPKE_t chk, int64_t interval);



#ifdef __cplusplus
}
#endif

#endif // _CHKPKE_H_INCLUDED_
