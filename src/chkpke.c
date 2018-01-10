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
#include <chkpke.h>
#include <ecurve.h>
#include <icarthash.h>
#include <libtasn1.h>
#include <sparsetree.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

typedef struct {
    element_ptr S;
    element_ptr R;
    int nR;
} _chkpke_node_data_t;

static void _clear_chk_node(_sparseTree_t *node) {
    _chkpke_node_data_t *nd;
    nd = (_chkpke_node_data_t *)node->nodeData;
    assert(nd != NULL);
    if (nd->S != NULL) {
        element_clear(nd->S);
        free(nd->S);
    }
    if (nd->R != NULL) {
        int i;
        for (i = 0; i < nd->nR; i++) {
            element_clear(&(nd->R[i]));
        }
        free(nd->R);
    }
    free(nd);
    return;
}

static void _init_chk_node(_sparseTree_t *node) {
    _chkpke_node_data_t *nd;
    nd = (_chkpke_node_data_t *)malloc(sizeof(_chkpke_node_data_t));
    nd->S = NULL;
    nd->R = NULL;
    nd->nR = 0;
    node->nodeData = (void *)nd;
    node->clear = _clear_chk_node;
    return;
}

// this definition is annoyingly private in PBC, but it is less messy to
// copy definition here than to export parameters to file and "screen scrape"
typedef struct {
  int exp2;
  int exp1;
  int sign1;
  int sign0;
  mpz_t r; // r = 2^exp2 + sign1 * 2^exp1 + sign0 * 1
  mpz_t q; // we work in E(F_q) (and E(F_q^2))
  mpz_t h; // r * h = q + 1
} *a_param_ptr;

static void _CHKPKE_extract_a_params(CHKPKE_t chk) {
    a_param_ptr p = chk->param->data;

    // copy and do not expose a_param_ptr
    mpz_set(chk->q, p->q);
    mpz_set(chk->r, p->r);
    mpz_set(chk->h, p->h);
    chk->p_exp2 = p->exp2;
    chk->p_exp1 = p->exp1;
    chk->p_sign1 = p->sign1;
    chk->p_sign0 = p->sign0;
    // validate params
    // q, r prime?
    assert(mpz_probab_prime_p(chk->q,10));
    assert(mpz_probab_prime_p(chk->r,10));
    {
        // r * h == q + 1 ? ( as r * h - 1 == q ? )
        mpz_t acc, t;
        mpz_init(acc);
        mpz_init(t);
        mpz_mul(acc, chk->r, chk->h);
        mpz_sub_ui(acc, acc, 1);
        assert(mpz_cmp(acc, chk->q) == 0);
        // r = 2^exp2 + sign1 * 2^exp1 + sign0 * 1 ?
        mpz_ui_pow_ui(acc, 2, chk->p_exp2);
        mpz_ui_pow_ui(t, 2, chk->p_exp1);
        if (chk->p_sign1 > 0) {
            mpz_add(acc, acc, t);
        } else {
            mpz_sub(acc, acc, t);
        }
        if (chk->p_sign0 > 0) {
            mpz_add_ui(acc, acc, 1);
        } else {
            mpz_sub_ui(acc, acc, 1);
        }
        assert(mpz_cmp(acc, chk->r) == 0);
        mpz_clear(t);
        mpz_clear(acc);
    }
    return;
}

static void _pbc_element_G1_to_affine_mpz(mpz_t x, mpz_t y, element_t e) {
    element_ptr t;
    t = element_x(e);
    element_to_mpz(x, t);
    t = element_y(e);
    element_to_mpz(y, t);
    return;
}

static void _pbc_element_G1_from_affine_mpz(element_t e, mpz_t x, mpz_t y, pairing_t p) {
    int ll, lb;
    size_t sz;
    char *buffer;
    element_clear(e);
    element_init_G1(e, p);
    ll = element_length_in_bytes_x_only(e);
    buffer = (char *)malloc(2 * ll * sizeof(char));
    // get size in bytes from size in bits (base 2)
    lb = (mpz_sizeinbase(x,2) + 7) / 8;
    assert(lb <= ll);
    lb = (mpz_sizeinbase(y,2) + 7) / 8;
    assert(lb <= ll);
    mpz_export(&buffer[0], &sz, 1, sizeof(char), 0, 0, x);
    assert(sz <= ll);
    if (sz < ll) {
        bzero(&buffer[0], ll);
        mpz_export(&buffer[ll-sz], &sz, 1, sizeof(char), 0, 0, x);
    }
    mpz_export(&buffer[ll], &sz, 1, sizeof(char), 0, 0, y);
    assert(sz <= ll);
    if (sz < ll) {
        bzero(&buffer[ll], ll);
        mpz_export(&buffer[ll + (ll-sz)], &sz, 1, sizeof(char), 0, 0, y);
    }
    lb = element_from_bytes(e, (unsigned char *)buffer);
    assert(lb == (2*ll));
    free(buffer);
    return;
}

static void _mpECP_set_pbc_element(mpECP_t pt, element_t e, mpECurve_t cv) {
    mpz_t x, y;
    mpz_init(x);
    mpz_init(y);
    _pbc_element_G1_to_affine_mpz(x, y, e);
    mpECP_set_mpz(pt, x, y, cv);
    mpz_clear(y);
    mpz_clear(x);
}

static void _pbc_element_set_mpECP(element_t e, mpECP_t pt, pairing_t p) {
    mpz_t x, y;
    mpz_init(x);
    mpz_init(y);
    mpz_set_mpECP_affine_x(x, pt);
    mpz_set_mpECP_affine_y(y, pt);
    _pbc_element_G1_from_affine_mpz(e, x, y, p);
    mpz_clear(y);
    mpz_clear(x);
}

static void _mpz_set_ull(mpz_t rop, uint64_t op) {
    mpz_import(rop, 1, -1, sizeof(op), 0, 0, &op);
}

void CHKPKE_init_Gen(CHKPKE_t chk, int qbits, int rbits, int depth, int order) {
    element_t alpha;
    element_t e_pt;
    mpECP_t ecp_pt;
    _chkpke_node_data_t *nd;
    chk->is_secret = true;
    assert(depth>0);
    assert(order>0);
    chk->depth = depth;
    chk->order = order;
    //printf("generating pairing\n");
    // generate random pairing (fields, etc)
    pbc_param_init_a_gen(chk->param, rbits, qbits);
    //printf("parameters:\n");
    //pbc_param_out_str(stdout, chk->param);
    pairing_init_pbc_param(chk->pairing, chk->param);
    // pick random P
    //printf("picking random P\n");
    element_init_G1(chk->P, chk->pairing);
    element_random(chk->P);
    // Q = alpha * P (alpha secret)
    //printf("picking random alpha, Q\n");
    element_init_Zr(alpha, chk->pairing);
    element_random(alpha);
    assert(element_is1(alpha) != 1);
    element_init_G1(chk->Q, chk->pairing);
    element_pow_zn(chk->Q, chk->P, alpha);
    assert(element_cmp(chk->Q, chk->P) != 0);
    // precalculate e(P,Q)
    //printf("applying pairing\n");
    element_init_GT(chk->ePQ, chk->pairing);
    element_pairing(chk->ePQ, chk->P, chk->Q);
    // private pairing params
    //printf("extracting params\n");
    mpz_init(chk->q);
    mpz_init(chk->r);
    mpz_init(chk->h);
    _CHKPKE_extract_a_params(chk);
    // setup G1 (and G2) curve space
    //printf("expressing as mpECurve_t\n");
    mpECurve_init(chk->C);
    {
        mpz_t a, b, x, y;
        mpz_init(a);
        mpz_init(b);
        mpz_init(x);
        mpz_init(y);
        mpz_set_ui(a, 1);
        mpz_set_ui(b, 0);
        _pbc_element_G1_to_affine_mpz(x, y, chk->P);
        mpECurve_set_mpz_ws(chk->C, chk->q, a, b, chk->r, chk->h, x, y, qbits);
        // extra validation step, ensure Q also on curve C
        _pbc_element_G1_to_affine_mpz(x, y, chk->Q);
        assert(mpECurve_point_check(chk->C, x, y));
        mpz_clear(y);
        mpz_clear(x);
        mpz_clear(b);
        mpz_clear(a);
    }
    // create a new (random) hash function on curve C
    //printf("initializing random hash function\n");
    icartHash_init(chk->H);
    icartHash_urandom(chk->H, chk->C);
    // initialize btree of order(# subnodes per node) = order
    //printf("initializing sparse tree\n");
    sparseTree_init(chk->tree, order, _init_chk_node);
    // precalculate pairing of Q and H(root node id = 0);
    assert(sparseTree_node_id(chk->tree) == 0);
    //printf("precalculating H(node(0))\n");
    element_init_G1(e_pt, chk->pairing);
    mpECP_init(ecp_pt);
    {
        uint64_t id;
        mpz_t x;
        mpz_init(x);
        // gmp doesn't provide convenience function for importing uint64_t (ull)
        id = sparseTree_node_id(chk->tree);
        //printf("id = %lx\n", id);
        _mpz_set_ull(x, id);
        //gmp_printf("id = %Zx\n", x);
        icartHash_hashval(ecp_pt, chk->H, x);
        mpz_clear(x);
    }
    _pbc_element_set_mpECP(e_pt, ecp_pt, chk->pairing);
    //{
    //    char *buffer;
    //    int sz;
    //    sz = mpECP_out_strlen(ecp_pt, 0);
    //    buffer = (char *)malloc((sz + 1) * sizeof(char));
    //    mpECP_out_str(buffer, ecp_pt, 0);
    //    buffer[sz] = 0;
    //    printf("ECP Point = %s\n", buffer);
    //    free(buffer);
    //}
    //element_printf("Element Point = %B\n", e_pt);
    element_init_GT(chk->eQH, chk->pairing);
    //printf("precalculating eQH\n");
    //element_printf("left  = %B\n", chk->Q);
    //element_printf("right = %B\n", e_pt);
    pairing_apply(chk->eQH, chk->Q, e_pt, chk->pairing);
    //element_random(chk->eQH);
    //printf("referencing node Data : node(0)\n");
    nd = (_chkpke_node_data_t *)chk->tree->nodeData;
    nd->nR = 0;
    nd->R = (element_ptr)NULL;
    nd->S = (element_ptr)malloc(sizeof(element_t));
    //printf("writing secret to node(0)\n");
    element_init_G1(nd->S, chk->pairing);
    element_mul(nd->S, e_pt, alpha);
}

//void CHKPKE_init(chkPKE_t chk);
void CHKPKE_clear(CHKPKE_t chk) {
    element_clear(chk->eQH);
    sparseTree_clear(chk->tree);
    icartHash_clear(chk->H);
    mpECurve_clear(chk->C);
    element_clear(chk->ePQ);
    element_clear(chk->Q);
    element_clear(chk->P);
    pairing_clear(chk->pairing);
    pbc_param_clear(chk->param);
    mpz_clear(chk->q);
    mpz_clear(chk->r);
    mpz_clear(chk->h);
}

extern const asn1_static_node fspke_asn1_tab[];

int _asn1_write_mpz_as_octet_string(asn1_node root, char *attribute, mpz_t value) {
    int length;
    int result;
    size_t lwrote;
    char *buffer;

    length = (mpz_sizeinbase(value, 2) + 7) / 8;
    buffer = (char *)malloc((length+1)*sizeof(char));
    assert(buffer != NULL);
    mpz_export(buffer, &lwrote, 1, sizeof(char), 0, 0, value);
    assert(lwrote == length);
    result = asn1_write_value(root, attribute, buffer, lwrote);
    assert(result == 0);
    free(buffer);
    return 5 + length;
}

int _asn1_write_int_as_integer(asn1_node root, char *attribute, int64_t value) {
    int nbytes;
    int result;
    char *buffer;
    if (value < 0) {
        if (value > (-((1ll<<7)-1))) {
            nbytes = 1;
        } else if (value > (-((1ll<<15)-1))) {
            nbytes = 2;
        } else if (value > (-((1ll<<31)-1))) {
            nbytes = 4;
        } else {
            nbytes = 8;
        }
    } else {
        if (value < (1 << 7)) {
            nbytes = 1;
        } else if (value < (1ll << 15)) {
            nbytes = 2;
        } else if (value < (1ll << 31)) {
            nbytes = 4;
        } else {
            nbytes = 8;
        }
    }
    buffer = (char *)malloc((nbytes + 2) * sizeof(char));
    assert(buffer != NULL);
    sprintf(buffer,"%ld", value);
    //printf("writing %ld (%s), length %d to %s\n", value, buffer, nbytes, attribute);
    result = asn1_write_value(root, attribute, buffer, 0);
    //printf("returned %d\n", result);
    assert(result == 0);
    free(buffer);
    return 5 + nbytes;
}

int _asn1_write_mpECP_as_octet_string(asn1_node root, char *attribute, mpECP_t value) {
    int length;
    int i;
    int result;
    char *sbuffer;
    char *buffer;

    length = mpECP_out_strlen(value,1);
    assert((length % 2) == 0);
    sbuffer = (char *)malloc((length + 1) * sizeof(char));
    buffer = (char *)malloc(((length >> 1) + 1) * sizeof(char));
    mpECP_out_str(sbuffer, value, 1);
    for (i = 0 ; i < (length >> 1); i++) {
        result = sscanf(&sbuffer[i << 1],"%2hhx",&buffer[i]);
        assert(result == 1);
    }
    result = asn1_write_value(root, attribute, buffer, (length >> 1));
    assert(result == 0);
    free(buffer);
    free(sbuffer);
    return 5 + (length >> 1);
}

char *CHKPKE_pubkey_encode_DER(CHKPKE_t chk, int interval) {
    ASN1_TYPE CHKPKE_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE pubkey_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int result;
    int length;
    int sum;
    size_t lwrote;
    char *buffer;

    sum = 0;

    result = asn1_array2tree(fspke_asn1_tab, &CHKPKE_asn1, asnError);

    if (result != 0) {
        asn1_perror (result);
        printf ("%s", asnError);
        assert(result == 0);
    }

    // create an empty ASN1 structure
    result = asn1_create_element(CHKPKE_asn1, "ForwardSecurePKE.CHKPublicKey",
        &pubkey_asn1);
    assert(result == 0);

    printf("-----------------\n");
    asn1_print_structure(stdout, pubkey_asn1, "", ASN1_PRINT_ALL);
    printf("-----------------\n");

    // Write pairing parameters to ASN1 structure
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "params.q", chk->q);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "params.r", chk->r);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "params.h", chk->h);

    sum += _asn1_write_int_as_integer(pubkey_asn1, "params.exp2", chk->p_exp2);
    sum += _asn1_write_int_as_integer(pubkey_asn1, "params.exp1", chk->p_exp1);
    sum += _asn1_write_int_as_integer(pubkey_asn1, "params.sign1", chk->p_sign1);
    sum += _asn1_write_int_as_integer(pubkey_asn1, "params.sign0", chk->p_sign0);

    // Write public base points (P, Q) to ASN1 structure

    {
        mpECP_t ppt, qpt;
        mpECP_init(ppt);
        mpECP_init(qpt);
        _mpECP_set_pbc_element(ppt, chk->P, chk->C);
        sum += _asn1_write_mpECP_as_octet_string(pubkey_asn1, "pPt", ppt);
        _mpECP_set_pbc_element(qpt, chk->Q, chk->C);
        sum += _asn1_write_mpECP_as_octet_string(pubkey_asn1, "qPt", qpt);
        assert(mpECP_cmp(ppt, qpt) != 0);
        mpECP_clear(ppt);
        mpECP_clear(qpt);
    }

    // validate export of params
    sum += 16;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (char *)malloc((sum) * sizeof(char));
    result = asn1_der_coding(pubkey_asn1, "params", buffer, &length, asnError);
    assert(result == 0);
    assert(length < sum);

    printf("-----------------\n");
    asn1_print_structure(stdout, pubkey_asn1, "", ASN1_PRINT_ALL);
    printf("-----------------\n");

    //free (buffer)
    //sum -= 16;

    asn1_delete_structure(&CHKPKE_asn1);
    return buffer;
}

//char *CHKPKE_privkey_encode_DER(CHKPKE_t, int interval);
