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

#ifndef _CHKPKE_H_INCLUDED_
#define _CHKPKE_H_INCLUDED_

#include <ecc.h>
#include <fspke/icarthash.h>
#include <fspke/sparsetree.h>
#include <gmp.h>
#include <pbc.h>
#include <stdbool.h>
#include <string.h>

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
    int64_t maxinterval;
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
unsigned char *CHKPKE_pubkey_encode_DER(CHKPKE_t chk, size_t *sz);
unsigned char *CHKPKE_privkey_encode_DER(CHKPKE_t chk, int64_t interval, size_t *sz);

// A delegate key is limited to a specific set of intervals (i.e. it has an end
// interval which may be less than the full life of the original key)
unsigned char *CHKPKE_privkey_encode_delegate_DER(CHKPKE_t chk, int64_t start, int64_t end, size_t *sz);

// decode routines return non-zero on decode error
int CHKPKE_init_pubkey_decode_DER(CHKPKE_t chk, unsigned char *der, size_t sz);
int CHKPKE_init_privkey_decode_DER(CHKPKE_t chk, unsigned char *der, size_t sz);

// Der attempts to derive the key material for a specific interval and returns
// -1 on failure (which will occur when attempting to derive a key for a past
// interval when the key has been pruned).
int CHKPKE_Der(CHKPKE_t chk, int64_t interval);

// Upd updates a key to only contain secrets for a specific interval and beyond,
// removing all secret information which could be used to decrypt messages from
// previous intervals. Returns 0 on success and nonzero on error (e.g. when
// attempting to derive secrets for a past interval for which no base secret
// exists)
int CHKPKE_Upd(CHKPKE_t chk, int64_t interval);

// Enc_DER uses the public key attributes to encode a plaintext message into a
// ciphertext. The "plaintext" message in this case is an element of Fp2 and
// the resulting ciphertext is a combination of Elliptic curve points in E(Fp)
// along with an element in Fp2. Enc_DER returns a ASN1 DER encoded byte buffer
// containing the ciphertext - the caller must use free() to release that
// memory once no longer in use. The message is encoded for a particular
// interval. Once a private key is updated to a future interval the resulting
// message cannot be decrypted.
unsigned char *CHKPKE_Enc_DER(CHKPKE_t chk, element_t plain, int64_t interval, size_t *sz);

// Dec_DER decodes an ASN1 DER encoded ciphertext into the original plaintext
// element based on the private key material and the specific interval. Dec
// returns 0 on success and -1 on error, e.g. if the key cannot be derived for
// the specified interval.
int CHKPKE_Dec_DER(element_t plain, CHKPKE_t chk, unsigned char *cipher, size_t sz,
        int64_t interval);


// find the minimum and maximum interval for which the key can derive
// secrets. The algorithm finds these values by finding the leftmost and
// rightmost valid elements in the key btree.
int64_t CHKPKE_privkey_min_interval(CHKPKE_t chk);
int64_t CHKPKE_privkey_max_interval(CHKPKE_t chk);

// convenience wrappers for handling Fp2 elements, so you don't have to
// interact directly with pbc library if you don't want to. You can simply
// create a random element, convert it to bytes (and hash, please) to use
// as a key for symmetric encryption, and then if you need to you can convert
// the bytes back into the element. NOTE: init_element_from_bytes presumes
// it is being passed an unitialized element. If the element was previously
// initialized it should be cleared with CHKPKE_element_clear first. 
unsigned char *CHKPKE_element_to_bytes(element_t e, size_t *sz);
int CHKPKE_init_element_from_bytes(element_t e, CHKPKE_t chk, unsigned char *bytes, size_t sz);
void CHKPKE_init_element(element_t e, CHKPKE_t chk);
void CHKPKE_init_random_element(element_t e, CHKPKE_t chk);
void CHKPKE_element_clear(element_t e);

#ifdef __cplusplus
}
#endif

#endif // _CHKPKE_H_INCLUDED_
