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
#include <chkpke.h>
#include <ecurve.h>
#include <portable_endian.h>
#include <icarthash.h>
#include <libtasn1.h>
#include <sparsetree.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
        nd->S = (element_ptr)NULL;
    }
    if (nd->R != NULL) {
        int i;
        for (i = 0; i < nd->nR; i++) {
            element_clear(&(nd->R[i]));
        }
        free(nd->R);
        nd->R = (element_ptr)NULL;
        nd->nR = 0;
    }
    return;
}

static void _clear_and_free_chk_node(_sparseTree_t *node) {
    _clear_chk_node(node);
    free(node->nodeData);
    return;
}

static void _init_chk_node(_sparseTree_t *node) {
    _chkpke_node_data_t *nd;
    nd = (_chkpke_node_data_t *)malloc(sizeof(_chkpke_node_data_t));
    nd->S = NULL;
    nd->R = NULL;
    nd->nR = 0;
    node->nodeData = (void *)nd;
    node->clear = _clear_and_free_chk_node;
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
    assert(mpz_probab_prime_p(chk->q,20));
    assert(mpz_probab_prime_p(chk->r,20));
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
    return;
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
    return;
}

static void _mpz_set_ull(mpz_t rop, uint64_t op) {
    mpz_import(rop, 1, -1, sizeof(op), 0, 0, &op);
    return;
}

static void _CHKPKE_setup_ECurve(CHKPKE_t chk, int qbits) {
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
    return;
}

static void _CHKPKE_precalc_H0(element_t e_pt, CHKPKE_t chk) {
    mpECP_t ecp_pt;

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
    mpECP_clear(ecp_pt);
    return;
}

void CHKPKE_init_Gen(CHKPKE_t chk, int qbits, int rbits, int depth, int order) {
    element_t e_pt;
    element_t alpha;
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
    _CHKPKE_setup_ECurve(chk, mpz_sizeinbase(chk->q,2));
    // create a new (random) hash function on curve C
    //printf("initializing random hash function\n");
    icartHash_init(chk->H);
    icartHash_urandom(chk->H, chk->C);
    // initialize btree of order(# subnodes per node) = order
    //printf("initializing sparse tree\n");
    sparseTree_init(chk->tree, order, _init_chk_node);
    // precalculate pairing of Q and H(root node id = 0);
    assert(sparseTree_node_id(chk->tree) == 0);
    element_init_G1(e_pt, chk->pairing);
    _CHKPKE_precalc_H0(e_pt, chk);
    //printf("precalc pairing eQH\n");
    element_init_GT(chk->eQH, chk->pairing);
    element_pairing(chk->eQH, chk->Q, e_pt);
    //printf("referencing node Data : node(0)\n");
    nd = (_chkpke_node_data_t *)chk->tree->nodeData;
    nd->nR = 0;
    nd->R = (element_ptr)NULL;
    nd->S = (element_ptr)malloc(sizeof(element_t));
    //printf("writing secret to node(0)\n");
    element_init_G1(nd->S, chk->pairing);
    element_mul_zn(nd->S, e_pt, alpha);
    element_clear(e_pt);
    element_clear(alpha);
    return;
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

static int _asn1_write_mpz_as_octet_string(asn1_node root, char *attribute, mpz_t value) {
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
    if (result != ASN1_SUCCESS) {
        int i;
        printf("error writing ");
        for (i = 0; i < lwrote; i++) {
            printf("%02X", buffer[i]);
        }
        printf(" to tag : %s\n", attribute);
    }
    assert(result == ASN1_SUCCESS);
    free(buffer);
    return 5 + length;
}

static int _asn1_write_int64_as_integer(asn1_node root, char *attribute, int64_t value) {
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
    assert(result == ASN1_SUCCESS);
    free(buffer);
    return 5 + nbytes;
}

static int _asn1_write_mpECP_as_octet_string(asn1_node root, char *attribute, mpECP_t value) {
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
    if (result != 0) {
        printf("error writing %s to %s\n", sbuffer, attribute);
    }
    assert(result == 0);
    free(buffer);
    free(sbuffer);
    return 5 + (length >> 1);
}

static int _asn1_write_element_t_as_CurvePoint(asn1_node root, char *attribute, element_t value) {
    //int result;
    int len;
    int sum;
    char *buffer;
    mpz_t x,y;

    mpz_init(x);
    mpz_init(y);

    _pbc_element_G1_to_affine_mpz(x, y, value);
    len = strlen(attribute) + 5;
    buffer = (char *)malloc((len + 1)*sizeof(char));

    strncpy(buffer, attribute, len);
    strncat(buffer, ".x", 5);
    sum = _asn1_write_mpz_as_octet_string(root, buffer, x);

    strncpy(buffer, attribute, len);
    strncat(buffer, ".y", 5);
    sum += _asn1_write_mpz_as_octet_string(root, buffer, y);

    mpz_clear(y);
    mpz_clear(x);
    // add some buffer for sequence of
    return sum + 5;
}

char *CHKPKE_pubkey_encode_DER(CHKPKE_t chk, int *sz) {
    ASN1_TYPE CHKPKE_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE pubkey_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int result;
    int length;
    int sum;
    //size_t lwrote;
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

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pubkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // Write pairing parameters to ASN1 structure
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "params.q", chk->q);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "params.r", chk->r);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "params.h", chk->h);

    sum += _asn1_write_int64_as_integer(pubkey_asn1, "params.exp2", chk->p_exp2);
    sum += _asn1_write_int64_as_integer(pubkey_asn1, "params.exp1", chk->p_exp1);
    sum += _asn1_write_int64_as_integer(pubkey_asn1, "params.sign1", chk->p_sign1);
    sum += _asn1_write_int64_as_integer(pubkey_asn1, "params.sign0", chk->p_sign0);

    // Write public base points (P, Q) to ASN1 structure

    //{
    //    mpECP_t ppt, qpt;
    //    mpECP_init(ppt);
    //    mpECP_init(qpt);
    //    _mpECP_set_pbc_element(ppt, chk->P, chk->C);
    //    sum += _asn1_write_mpECP_as_octet_string(pubkey_asn1, "pPt", ppt);
    //    _mpECP_set_pbc_element(qpt, chk->Q, chk->C);
    //    sum += _asn1_write_mpECP_as_octet_string(pubkey_asn1, "qPt", qpt);
    //    assert(mpECP_cmp(ppt, qpt) != 0);
    //    mpECP_clear(ppt);
    //    mpECP_clear(qpt);
    //}

    sum += _asn1_write_element_t_as_CurvePoint(pubkey_asn1, "pPt", chk->P);
    sum += _asn1_write_element_t_as_CurvePoint(pubkey_asn1, "qPt", chk->Q);

    // write tree parameters
    sum += _asn1_write_int64_as_integer(pubkey_asn1, "depth", chk->depth);
    sum += _asn1_write_int64_as_integer(pubkey_asn1, "order", chk->order);

    // write hash function parameters - generator point
    //{
    //    mpz_t x,y;
    //    mpz_init(x);
    //    mpz_init(y);
    //    mpz_set_mpECP_affine_x(x, chk->H->pt);
    //    mpz_set_mpECP_affine_y(y, chk->H->pt);
    //    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.g.x", x);
    //    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.g.y", y);
    //    mpz_clear(x);
    //    mpz_clear(y);
    //}
    {
        element_t gH;
        element_init_G1(gH, chk->pairing);
        _pbc_element_set_mpECP(gH, chk->H->pt, chk->pairing);
        sum += _asn1_write_element_t_as_CurvePoint(pubkey_asn1, "h.g", gH);
        element_clear(gH);
    }

    // Carter-Wegman hash function A
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.cwa.p", chk->H->cwa->p);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.cwa.a", chk->H->cwa->a->i);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.cwa.b", chk->H->cwa->b->i);
    // Carter-Wegman hash function A
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.cwb.p", chk->H->cwb->p);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.cwb.a", chk->H->cwb->a->i);
    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.cwb.b", chk->H->cwb->b->i);

    // validate export
    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (char *)malloc((sum) * sizeof(char));
    result = asn1_der_coding(pubkey_asn1, "", buffer, &length, asnError);
    assert(result == 0);
    assert(length < sum);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pubkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    asn1_delete_structure(&pubkey_asn1);
    asn1_delete_structure(&CHKPKE_asn1);
    *sz = length;
    return buffer;
}

// derive the secrets for this specific node... recurse up tree as needed
// to derive as the secrets are calculated only when needed (lazy allocation)
static int _CHKPKE_der_for_node(CHKPKE_t chk, int depth, int64_t ordinal) {
    sparseTree_ptr_t node;
    sparseTree_ptr_t parent;
    _chkpke_node_data_t *nd;
    _chkpke_node_data_t *pnd;

    //printf("seeking key for %d, %ld\n", depth, ordinal);
    node = sparseTree_find_by_address(chk->tree, depth, ordinal);
    nd = (_chkpke_node_data_t *)node->nodeData;

    //printf("found\n");
    if (nd->S != NULL) {
        assert (nd->nR == depth);
        return 0;
    }

    if (depth == 0) {
        // got to root node without finding a secret S
        return -1;
    }

    parent = node->parent;
    pnd = (_chkpke_node_data_t *)parent->nodeData;
    if (_CHKPKE_der_for_node(chk, parent->depth, parent->ordinal) != 0) {
        return -1;
    }

    //printf("Der for (%d, %ld)\n", node->depth, node->ordinal);

    nd->S = (element_ptr)malloc(sizeof(struct element_s));
    nd->R = (element_ptr)malloc(depth*sizeof(struct element_s));
    nd->nR = depth;
    {
        int i;
        mpz_t x;
        element_t pw, Hpw, Hcp;
        mpECP_t H;
        mpz_init(x);
        element_init_Zr(pw, chk->pairing);
        element_init_G1(Hcp, chk->pairing);
        element_init_G1(Hpw, chk->pairing);
        mpECP_init(H);

        _mpz_set_ull(x, sparseTree_node_id(node));
        //printf("calculating Hash\n");
        icartHash_hashval(H, chk->H, x);
        _pbc_element_set_mpECP(Hcp, H, chk->pairing);
        element_random(pw);

        for (i = 0; i < (depth-1); i++) {
            //printf("copying R[%d] from parent\n", i);
            element_init_G1(&(nd->R[i]), chk->pairing);
            element_set(&(nd->R[i]), &(pnd->R[i]));
        }

        //printf("appending R[%d]\n", depth-1);
        element_init_G1(&(nd->R[depth-1]), chk->pairing);
        element_pow_zn(&(nd->R[depth-1]), chk->P, pw);
        //printf("deriving S from parent, random\n");
        element_pow_zn(Hpw, Hcp, pw);
        element_init_G1(nd->S, chk->pairing);
        element_add(nd->S, pnd->S, Hpw);

        mpECP_clear(H);
        element_clear(Hpw);
        element_clear(Hcp);
        element_clear(pw);
        mpz_clear(x);
    }
    return 0;
}

int CHKPKE_Der(CHKPKE_t chk, int64_t interval) {
    return _CHKPKE_der_for_node(chk, chk->depth, interval);
}

// simple singly linked list
typedef struct __chkpke_node_config_t {
    _chkpke_node_data_t *nd;
    int depth;
    int64_t ordinal;
    struct __chkpke_node_config_t *next;
} _chkpke_node_config_t;

// build a minimal list of keys to represent a specific interval number
// keeping in mind that keys are hierarchical, so parent can encode all
// children (so if you don't want ALL the children then you need to
// encode the children you want and not the parent)
static _chkpke_node_config_t *_CHKPKE_keylist_for_depth_interval(CHKPKE_t chk, int depth, int64_t start, int64_t end) {
    _chkpke_node_config_t *head = (_chkpke_node_config_t *)NULL;
    _chkpke_node_config_t *next = (_chkpke_node_config_t *)NULL;
    _chkpke_node_config_t *nconfig = (_chkpke_node_config_t *)NULL;
    sparseTree_ptr_t node;
    int64_t i;
    int64_t upstart, upend, startstop, beginend;
    //printf("keylist head @ (%d, %ld, %ld)\n", depth, start, end);

    if (depth == 0) {
        assert(start == 0);
        assert(end == 0);
    }

    if (end < start) return (_chkpke_node_config_t *)NULL;

    // validate that keys exist for start, end - all keys between implied
    if ((_CHKPKE_der_for_node(chk, depth, start) != 0) ||
        (_CHKPKE_der_for_node(chk, depth, end) != 0)) {
        //printf("keylist head @ (%d, %ld, %ld)\n", depth, start, end);
        //printf("unable to generate keys\n");
        return (_chkpke_node_config_t *)NULL;
    }

    if ((start % chk->order) == 0) {
        // start on block boundary
        if ((end - start) >= chk->order) {
            // contains all of btree leaves of first "block"
            upstart = start / chk->order;
            upend = end / chk->order;
            startstop = start - 1;
            if ((end % chk->order) == (chk->order - 1)) {
                // start and end on boundary
                beginend = end + 1;
            } else {
                // start on boundary and end not
                beginend = end - (end % chk->order);
                upend -= 1;
            }
        } else if ((end - start) == (chk->order - 1)) {
            // exactly one block on boundary
            upstart = start / chk->order;
            upend = upstart;
            startstop = start - 1;
            beginend = end + 1;
        } else {
            // less than a single block
            upstart = 0;
            upend = -1;
            startstop = end;
            beginend = end + 1;
        }
    } else {
        // start not on boundary
        if ((end / chk->order) <= ((start / chk->order) + 1)) {
            // both in the same block or in consecutive
            upstart = 0;
            upend = -1;
            startstop = end;
            beginend = end + 1;
        } else {
            // at least one complete block in the middle
            upstart = start / chk->order + 1;
            upend = end / chk->order;
            startstop = (upstart * chk->order) - 1 ;
            if ((end % chk->order) == (chk->order - 1)) {
                // end on block boundary
                beginend = end + 1;
            } else {
                // end not on boundary
                beginend = upend * chk->order;
                upend -= 1;
            }
        }
    }

    // encode node + right from current level
    //upstart = start + ((chk->order - (start % chk->order)) % chk->order) ;
    //upend  = (end + 1) - ((end + 1) % chk->order) ;

    //printf("upstart, upend = %ld, %ld\n", upstart, upend);
    //printf("startstop, beginend = %ld, %ld\n", startstop, beginend);

    //printf("building keylist\n");

    for (i = start; i <= startstop; i++) {
        nconfig = (_chkpke_node_config_t *)malloc(sizeof(_chkpke_node_config_t));
        if (head == NULL) {
            head = nconfig;
            next = head;
        } else {
            assert(next != NULL);
            next->next = nconfig;
            next = nconfig;
        }
        nconfig->next = (_chkpke_node_config_t *)NULL;
        //printf("node @ (%d, %ld)\n", depth, i);
        // must call _der_for_node to populate R,S in nodeData
        assert(_CHKPKE_der_for_node(chk, depth, i) == 0);
        node = sparseTree_find_by_address(chk->tree, depth, i);
        nconfig->nd = (_chkpke_node_data_t *)node->nodeData;
        nconfig->depth = depth;
        nconfig->ordinal = i;
    }

    for (i = beginend; i <= end; i++) {
        nconfig = (_chkpke_node_config_t *)malloc(sizeof(_chkpke_node_config_t));
        if (head == NULL) {
            head = nconfig;
            next = head;
        } else {
            assert(next != NULL);
            next->next = nconfig;
            next = nconfig;
        }
        nconfig->next = (_chkpke_node_config_t *)NULL;
        //printf("node @ (%d, %ld)\n", depth, i);
        // must call _der_for_node to populate R,S in nodeData
        assert(_CHKPKE_der_for_node(chk, depth, i) == 0);
        node = sparseTree_find_by_address(chk->tree, depth, i);
        nconfig->nd = (_chkpke_node_data_t *)node->nodeData;
        nconfig->depth = depth;
        nconfig->ordinal = i;
    }

    // encode parent + 1 from next level up (and recurse)
    if (upend >= upstart) {
        nconfig = _CHKPKE_keylist_for_depth_interval(chk, depth - 1, upstart, upend);
        if (head == NULL) {
            head = nconfig;
        } else {
            assert(next != NULL);
            next->next = nconfig;
        }
    }

    return head;
}

static int64_t _expi64(int64_t a, int64_t e) {
    assert(e >= 0);
    assert(e < 64);
    if (e == 0) return 1;
    return a * _expi64(a, e - 1);
}

static void _validate_keylist(_chkpke_node_config_t *nconfig, int depth, int order, int64_t start, int64_t end) {
    _chkpke_node_config_t *head;
    _chkpke_node_config_t *next;
    int64_t minkey, maxkey, k, kk, j, jj;

    // find min, max key
    head = nconfig;
    minkey = head->ordinal * _expi64(order, (depth - head->depth));
    maxkey = minkey + _expi64(order, depth - head->depth) - 1;
    //printf("key @ %d, %ld spans %ld -> %ld\n", head->depth, head->ordinal, minkey, maxkey);
    head = head->next;
    while (head != NULL) {
        k = head->ordinal * _expi64(order, (depth - head->depth));
        if (k < minkey) minkey = k;
        kk = k + _expi64(order, depth - head->depth) - 1;
        if (kk > maxkey) maxkey = kk;
        //printf("key @ %d, %ld spans %ld -> %ld\n", head->depth, head->ordinal, k, kk);
        head = head->next;
    }
    assert(minkey == start);
    assert(maxkey == end);

    // ensure keys are contiguous and do not overlap, no duplicates
    head = nconfig;
    while (head != NULL) {
        k = head->ordinal * _expi64(order, (depth - head->depth));
        kk = k + _expi64(order, depth - head->depth) - 1;
        j = kk;
        next = nconfig;
        while (j != kk + 1) {
            if (next == NULL) {
                //printf("unmatched key @ %d, %ld spans %ld -> %ld\n", head->depth, head->ordinal, k, kk);
                assert(kk == end);
                break;
            }
            j = next->ordinal * _expi64(order, (depth - next->depth));
            jj = j + _expi64(order, depth - next->depth) - 1;
            if (next != head) {
                assert(j != k);
                assert(jj != kk);
                if (j > k) assert (j > kk);
                if (k > j) assert (k > jj);
            }
            next = next->next;
        }
        head = head->next;
    }

    return;
}

static _chkpke_node_config_t *_CHKPKE_keylist_for_start_end(CHKPKE_t chk, int64_t start, int64_t end) {
    _chkpke_node_config_t *head;
    //_chkpke_node_config_t *next;

    head = _CHKPKE_keylist_for_depth_interval(chk, chk->depth, start, end);

    if (head != NULL) _validate_keylist(head, chk->depth, chk->order, start, end);

    //next = head;
    //printf("-- list out start --\n");
    //while (next != (_chkpke_node_config_t *)NULL) {
    //    printf("node (%d, %ld) ->\n", next->depth, next->ordinal);
    //    for (i = 0; i < next->nd->nR; i++) {
    //        printf("    R[%ld] :", i);
    //        element_printf("%B\n", &(next->nd->R[i]));
    //    }
    //    printf("    ");
    //    element_printf("%B\n", next->nd->S);
    //    next = next->next;
    //}
    //printf("-- list out end --\n");

    return head;
}

static _chkpke_node_config_t *_CHKPKE_keylist_for_interval(CHKPKE_t chk, int64_t interval) {
    int64_t e;

    e = _expi64(chk->order, chk->depth) - 1;

    return _CHKPKE_keylist_for_start_end(chk, interval, e);
}

static void _CHKPKE_keylist_clean(_chkpke_node_config_t *list) {
    _chkpke_node_config_t *head;
    _chkpke_node_config_t *next;

    head = list;
    while (head != NULL) {
        next = head->next;
        free(head);
        head = next;
    }
    return;
}

int CHKPKE_Upd(CHKPKE_t chk, int64_t interval) {
    _chkpke_node_config_t *keylist;
    sparseTree_ptr_t node, parent, sibling;
    int i;

    // ensure all secrets derived for interval
    //printf("Upd for interval %ld\n", interval);
    keylist = _CHKPKE_keylist_for_interval(chk, interval);
    if (keylist == NULL) return -1;
    _CHKPKE_keylist_clean(keylist);

    node = sparseTree_find_by_address(chk->tree, chk->depth, interval);
    parent = node->parent;
    //printf("node found = (%d, %ld)\n", node->depth, node->ordinal);

    // clear secrets from parent and left-siblings, recurse up tree
    // parent == NULL implies node is the tree root node
    while (parent != NULL) {

        //printf("clearing parent (%d, %ld), left from (%d, %ld)\n", parent->depth, parent->ordinal, node->depth, node->ordinal);

        for (i = 0; i < chk->order; i++) {
            // quit once we get to current node;
            sibling = parent->child[i];
            if (sibling == node) break;
            if (sibling != NULL) {
                // clearing sibling nodes also clears/frees allocated child nodes
                //printf("deleting sibling (%d, %ld)\n", sibling->depth, sibling->ordinal);
                sparseTree_clear(sibling);
                parent->child[i] = (_sparseTree_t *)NULL;
            }
        }

        // error if we didn't abort loop early
        assert(i < chk->order);

        // clear secrets for parent node
        _clear_chk_node(parent);
        node = parent;
        parent = node->parent;
    }
    //printf("cleared all previous secrets\n");

    //assert(node == chk->tree);
    // clear the root node... all secrets can be derived from root secret
    //_clear_chk_node(chk->tree);
    return 0;
}

char *CHKPKE_privkey_encode_delegate_DER(CHKPKE_t chk, int64_t start, int64_t end, int *sz) {
    _chkpke_node_config_t *keylist;
    _chkpke_node_config_t *nextkey;
    ASN1_TYPE CHKPKE_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE privkey_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int result;
    int length;
    int sum;
    //size_t lwrote;
    char *buffer;

    sum = 0;

    keylist = _CHKPKE_keylist_for_start_end(chk, start, end);
    if (keylist == (_chkpke_node_config_t *)NULL) {
        return (char *)NULL;
    }

    result = asn1_array2tree(fspke_asn1_tab, &CHKPKE_asn1, asnError);

    if (result != 0) {
        asn1_perror (result);
        printf ("%s", asnError);
        assert(result == 0);
    }

    // create an empty ASN1 structure
    result = asn1_create_element(CHKPKE_asn1, "ForwardSecurePKE.CHKPrivateKey",
        &privkey_asn1);
    assert(result == 0);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, privkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // Write pairing parameters to ASN1 structure
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.params.q", chk->q);
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.params.r", chk->r);
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.params.h", chk->h);

    sum += _asn1_write_int64_as_integer(privkey_asn1, "pubkey.params.exp2", chk->p_exp2);
    sum += _asn1_write_int64_as_integer(privkey_asn1, "pubkey.params.exp1", chk->p_exp1);
    sum += _asn1_write_int64_as_integer(privkey_asn1, "pubkey.params.sign1", chk->p_sign1);
    sum += _asn1_write_int64_as_integer(privkey_asn1, "pubkey.params.sign0", chk->p_sign0);

    // Write public base points (P, Q) to ASN1 structure

    //{
    //    mpECP_t ppt, qpt;
    //    mpECP_init(ppt);
    //    mpECP_init(qpt);
    //    _mpECP_set_pbc_element(ppt, chk->P, chk->C);
    //    sum += _asn1_write_mpECP_as_octet_string(pubkey_asn1, "pPt", ppt);
    //    _mpECP_set_pbc_element(qpt, chk->Q, chk->C);
    //    sum += _asn1_write_mpECP_as_octet_string(pubkey_asn1, "qPt", qpt);
    //    assert(mpECP_cmp(ppt, qpt) != 0);
    //    mpECP_clear(ppt);
    //    mpECP_clear(qpt);
    //}

    sum += _asn1_write_element_t_as_CurvePoint(privkey_asn1, "pubkey.pPt", chk->P);
    sum += _asn1_write_element_t_as_CurvePoint(privkey_asn1, "pubkey.qPt", chk->Q);

    // write tree parameters
    sum += _asn1_write_int64_as_integer(privkey_asn1, "pubkey.depth", chk->depth);
    sum += _asn1_write_int64_as_integer(privkey_asn1, "pubkey.order", chk->order);

    // write hash function parameters - generator point
    //{
    //    mpz_t x,y;
    //    mpz_init(x);
    //    mpz_init(y);
    //    mpz_set_mpECP_affine_x(x, chk->H->pt);
    //    mpz_set_mpECP_affine_y(y, chk->H->pt);
    //    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.g.x", x);
    //    sum += _asn1_write_mpz_as_octet_string(pubkey_asn1, "h.g.y", y);
    //    mpz_clear(x);
    //    mpz_clear(y);
    //}
    {
        element_t gH;
        element_init_G1(gH, chk->pairing);
        _pbc_element_set_mpECP(gH, chk->H->pt, chk->pairing);
        sum += _asn1_write_element_t_as_CurvePoint(privkey_asn1, "pubkey.h.g", gH);
        element_clear(gH);
    }

    // Carter-Wegman hash function A
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.h.cwa.p", chk->H->cwa->p);
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.h.cwa.a", chk->H->cwa->a->i);
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.h.cwa.b", chk->H->cwa->b->i);
    // Carter-Wegman hash function A
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.h.cwb.p", chk->H->cwb->p);
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.h.cwb.a", chk->H->cwb->a->i);
    sum += _asn1_write_mpz_as_octet_string(privkey_asn1, "pubkey.h.cwb.b", chk->H->cwb->b->i);
    
    //printf("privkey export : pubkey complete\n");

    nextkey = keylist;
    while (nextkey != NULL) {
        int i;
        mpECP_t pt;

        //printf("writing key for (%d, %ld)\n", nextkey->depth, nextkey->ordinal);

        mpECP_init(pt);
        // create a new secret
        result = asn1_write_value (privkey_asn1, "secrets", "NEW", 1);
        assert(result == 0);
        sum += 12;

        sum += _asn1_write_int64_as_integer(privkey_asn1, "secrets.?LAST.id.depth", nextkey->depth);
        sum += _asn1_write_int64_as_integer(privkey_asn1, "secrets.?LAST.id.ordinal", nextkey->ordinal);

        // sanity check... for nodes with secrets, nR should = depth
        assert(nextkey->nd->nR == nextkey->depth);

        for (i = 0; i < nextkey->nd->nR; i++) {
            result = asn1_write_value (privkey_asn1, "secrets.?LAST.r", "NEW", 1);
            assert(result == 0);

            _mpECP_set_pbc_element(pt, &(nextkey->nd->R[i]), chk->C);
            sum += _asn1_write_mpECP_as_octet_string(privkey_asn1, "secrets.?LAST.r.?LAST", pt);
        }

        _mpECP_set_pbc_element(pt, nextkey->nd->S, chk->C);
        sum += _asn1_write_mpECP_as_octet_string(privkey_asn1, "secrets.?LAST.s", pt);
        mpECP_clear(pt);
        nextkey = nextkey->next;
    }

    // validate export
    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (char *)malloc((sum) * sizeof(char));
    result = asn1_der_coding(privkey_asn1, "", buffer, &length, asnError);
    assert(result == 0);
    assert(length < sum);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, privkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    asn1_delete_structure(&privkey_asn1);
    asn1_delete_structure(&CHKPKE_asn1);
    _CHKPKE_keylist_clean(keylist);
    *sz = length;
    return buffer;
}

char *CHKPKE_privkey_encode_DER(CHKPKE_t chk, int64_t interval, int *sz) {
    int64_t e;

    e = _expi64(chk->order, chk->depth) - 1;

    return CHKPKE_privkey_encode_delegate_DER(chk, interval, e, sz);
}

static int _asn1_read_mpz_from_octet_string(mpz_t value, asn1_node root, char *attribute) {
    int result, length, lread;
    char *buffer;

    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    // allocate
    buffer = (char *)malloc((length+1)*sizeof(char));
    lread = length + 1;
    result = asn1_read_value(root, attribute, buffer, &lread);
    if (result != ASN1_SUCCESS) goto cleanup_on_error;
    //assert(result == 0);
    if (lread != length) goto cleanup_on_error;
    //assert(lread == length);
    mpz_import(value, lread, 1, sizeof(char), 0, 0, buffer);
    free(buffer);
    return 0;
    
cleanup_on_error:
    free(buffer);
    return -1;
}

static int _asn1_read_mpECP_from_octet_string(mpECP_t value, asn1_node root, char *attribute, mpECurve_t cv) {
    int result, length, lread;
    char *buffer;
    char *sbuffer;

    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    // allocate
    buffer = (char *)malloc((length+1)*sizeof(char));
    lread = length + 1;
    result = asn1_read_value(root, attribute, buffer, &lread);
    if (result != ASN1_SUCCESS) goto cleanup_on_error;
    //assert(result == 0);
    if (lread != length) goto cleanup_on_error;
    sbuffer = (char *)malloc(((length * 2)+1) * sizeof(char));
    //assert(lread == length);
    {
        int i;
        //printf("reading ECP point from (%d bytes): ", length);
        for (i = 0 ; i < length; i++) {
            sprintf(&sbuffer[2 * i], "%02X", (unsigned char)buffer[i]);
        }
        sbuffer[2 * length] = 0;
        //printf("%s\n", sbuffer);
    }
    result = mpECP_set_str(value, sbuffer, cv);
    //printf("result = %d\n", result);
    free(sbuffer);
    free(buffer);
    return result;

cleanup_on_error:
    free(buffer);
    return -1;
}

static int _asn1_read_int_from_integer(int *value, asn1_node root, char *attribute) {
    int result, length, lread;
    uint32_t uvalue = 0;
    //char *buffer;

    assert(sizeof(int) == 4);
    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    if (length > sizeof(int)) return -1;
    lread = sizeof(int);
    result = asn1_read_value(root, attribute, &uvalue, &lread);
    if (result != ASN1_SUCCESS) return -1;
    //assert(result == 0);
    if (lread != length) return -1;
    //assert(lread == length);
    //{
    //    unsigned char *bytes;
    //    int i;
    //
    //    printf("read %d byte integer as ", length);
    //    bytes = (unsigned char *)&uvalue;
    //    for (i = 0; i < length; i++) {
    //        printf("%02X ", bytes[i]);
    //    }
    //    printf(" = %d\n", (int)uvalue);
    //}
    *value = (int)be32toh(uvalue);
    //printf("value = 0x%08X", *value);
    if (length < sizeof(int)) {
        *value >>= ((sizeof(int) - length) * 8) ;
    }
    //printf("adjusted value = %d\n", *value);
    return 0;
}

static int _asn1_read_int64_from_integer(int64_t *value, asn1_node root, char *attribute) {
    int result, length, lread;
    uint64_t uvalue = 0;
    //char *buffer;

    assert(sizeof(int64_t) == 8);
    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    if (length > sizeof(int64_t)) return -1;
    lread = sizeof(int64_t);
    result = asn1_read_value(root, attribute, &uvalue, &lread);
    if (result != ASN1_SUCCESS) return -1;
    //assert(result == 0);
    if (lread != length) return -1;
    //assert(lread == length);
    //{
    //    unsigned char *bytes;
    //    int i;
    //
    //    printf("read %d byte integer as ", length);
    //    bytes = (unsigned char *)&uvalue;
    //    for (i = 0; i < length; i++) {
    //        printf("%02X ", bytes[i]);
    //    }
    //    printf(" = %ld\n", (int64_t)uvalue);
    //}
    *value = (int64_t)be64toh(uvalue);
    //printf("value = 0x%016lX\n", *value);
    if (length < sizeof(int64_t)) {
        *value >>= ((sizeof(int64_t) - length) * 8) ;
    }
    //printf("adjusted value = %ld\n", *value);
    return 0;
}

static int _asn1_read_element_t_from_CurvePoint(element_t value, asn1_node root, char *attribute) {
    int result, length, lread, len, len_element;
    char *buffer, *abuffer;

    len = strlen(attribute) + 5;
    abuffer = (char *)malloc((len + 1)*sizeof(char));

    // call read_value with NULL buffer to get length
    strncpy(abuffer, attribute, len);
    strncat(abuffer, ".x", 5);
    length = 0;
    result = asn1_read_value(root, abuffer, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    // allocate
    len_element = element_length_in_bytes_x_only(value);
    //printf("length string = %d, length element expected = %d\n", length, len_element);
    assert(len_element >= length);
    //printf("allocating space for 2x %d-bit x,y values\n", (length * 8));
    buffer = (char *)malloc(((len_element * 2) + 1)*sizeof(char));
    bzero(buffer, len_element * 2);

    lread = length + 1;
    result = asn1_read_value(root, abuffer, &buffer[len_element-length], &lread);
    if (result != ASN1_SUCCESS) return -1;
    //printf("read X\n");
    //assert(result == 0);
    if (lread != length) return -1;
    //assert(lread == length);
    //{
    //    int i;
    //    printf("read X (%s) as :", abuffer);
    //    for (i = 0; i < length; i++) {
    //        printf("%02X", (unsigned char)buffer[i]);
    //    }
    //    printf("\n");
    //}

    strncpy(abuffer, attribute, len);
    strncat(abuffer, ".y", 5);
    length = 0;
    result = asn1_read_value(root, abuffer, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    assert(len_element >= length);
    lread = length + 1;
    result = asn1_read_value(root, abuffer, &buffer[(2*len_element)-length], &lread);
    if (result != ASN1_SUCCESS) return -1;
    //printf("read Y\n");
    //assert(result == 0);
    if (lread != length) return -1;
    //assert(lread == length);
    //{
    //    int i;
    //    printf("read Y (%s) as :", abuffer);
    //    for (i = 0; i < length; i++) {
    //        printf("%02X", (unsigned char)buffer[i+length]);
    //    }
    //    printf("\n");
    //}

    element_from_bytes(value, (unsigned char*)buffer);
    free(buffer);
    free(abuffer);
    return 0;
}

static char *_gen_pbc_param_a_string(CHKPKE_t chk) {
    int sz;
    char *buffer;

    // upper bounds on size based on bits in q
    // fixed text, spaces, etc ~= 42 chars, round up to 64
    // assume q,r,h all <=exp2 bits long, >4 bits per byte
    // assume exp2, exp1, sign1, sign0 all <10 bytes
    sz = 48 + ((chk->p_exp2 * 3) / 4) + (4 * 10);
    buffer = (char *)malloc(sz * sizeof(char));

    gmp_sprintf(buffer,
        "type a\nq %Zd\nh %Zd\nr %Zd\nexp2 %d\nexp1 %d\nsign1 %d\nsign0 %d\n",
        chk->q, chk->h, chk->r, chk->p_exp2, chk->p_exp1, chk->p_sign1,
        chk->p_sign0);
    return buffer;
}

int CHKPKE_init_pubkey_decode_DER(CHKPKE_t chk, char *der, int sz) {
    ASN1_TYPE CHKPKE_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE pubkey_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    char *param_string;
    int result;
    mpECurve_t hcv;
    cwHash_t cwa, cwb;
    mpz_t p, a, b;
    element_t e_pt;
    int qbits;
    //int length;
    //int lwrote;
    //char *buffer;

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

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pubkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    result = asn1_der_decoding(&pubkey_asn1, der, sz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pubkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // Initialize pairing parameter fields
    mpz_init(chk->q);
    mpz_init(chk->r);
    mpz_init(chk->h);

    // Read pairing parameters from ASN1 structure
    result = _asn1_read_mpz_from_octet_string(chk->q, pubkey_asn1, "params.q");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("q parsed as : %Zd (0x%Zx)\n", chk->q, chk->q);

    result = _asn1_read_mpz_from_octet_string(chk->r, pubkey_asn1, "params.r");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("r parsed as : %Zd (0x%Zx)\n", chk->r, chk->r);

    result = _asn1_read_mpz_from_octet_string(chk->h, pubkey_asn1, "params.h");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("h parsed as : %Zd (0x%Zx)\n", chk->h, chk->h);

    result = _asn1_read_int_from_integer(&(chk->p_exp2), pubkey_asn1, "params.exp2");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("exp2 parsed as : %d (0x%x)\n", chk->p_exp2, chk->p_exp2);

    result = _asn1_read_int_from_integer(&(chk->p_exp1), pubkey_asn1, "params.exp1");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("exp1 parsed as : %d (0x%x)\n", chk->p_exp1, chk->p_exp1);

    result = _asn1_read_int_from_integer(&(chk->p_sign1), pubkey_asn1, "params.sign1");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("sign1 parsed as : %d (0x%x)\n", chk->p_sign1, chk->p_sign1);

    result = _asn1_read_int_from_integer(&(chk->p_sign0), pubkey_asn1, "params.sign0");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("sign0 parsed as : %d (0x%x)\n", chk->p_sign0, chk->p_sign0);

    param_string = _gen_pbc_param_a_string(chk);
    //printf("-----\nParams\n-----\n%s-----\n", param_string);

    result = pbc_param_init_set_str(chk->param, param_string);
    assert(result == 0);
    if (result != 0) goto error_cleanup1;
    free(param_string);

    //printf("init pairing\n");
    pairing_init_pbc_param(chk->pairing, chk->param);
    //printf("init curve\n");
    mpECurve_init(chk->C);
    //printf("setup curve\n");
    qbits = mpz_sizeinbase(chk->q, 2);
    //printf("setup curve qbits = %d\n", qbits);

    element_init_G1(chk->P,chk->pairing);
    element_init_G1(chk->Q,chk->pairing);
    element_init_GT(chk->ePQ,chk->pairing);
    mpECurve_init(hcv);
    cwHash_init(cwa);
    cwHash_init(cwb);
    mpz_init(p);
    mpz_init(a);
    mpz_init(b);

    result = _asn1_read_element_t_from_CurvePoint(chk->P, pubkey_asn1, "pPt");
    if (result != 0) goto error_cleanup2;
    //element_printf("P: %B\n", chk->P);

    result = _asn1_read_element_t_from_CurvePoint(chk->Q, pubkey_asn1, "qPt");
    if (result != 0) goto error_cleanup2;
    //element_printf("Q: %B\n", chk->Q);

    element_pairing(chk->ePQ, chk->P, chk->Q);

    _CHKPKE_setup_ECurve(chk, qbits);

    result = _asn1_read_int_from_integer(&(chk->depth), pubkey_asn1, "depth");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("depth parsed as : %d (0x%x)\n", chk->depth, chk->depth);

    result = _asn1_read_int_from_integer(&(chk->order), pubkey_asn1, "order");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("order parsed as : %d (0x%x)\n", chk->order, chk->order);

    {
        mpz_t x,y;

        mpz_init(x);
        result = _asn1_read_mpz_from_octet_string(x, pubkey_asn1, "h.g.x");
        if (result != 0) {
            mpz_clear(x);
            goto error_cleanup2;
        }
        //gmp_printf("g.x parsed as : %Zd (0x%Zx)\n", x, x);

        mpz_init(y);
         result = _asn1_read_mpz_from_octet_string(y, pubkey_asn1, "h.g.y");
        if (result != 0) {
            mpz_clear(y);
            mpz_clear(x);
            goto error_cleanup2;
        }
        //gmp_printf("g.y parsed as : %Zd (0x%Zx)\n", y, y);

        mpECurve_set_mpz_ws(hcv, chk->q, chk->C->coeff.ws.a->i,
            chk->C->coeff.ws.b->i, chk->r, chk->h, x, y, qbits);

        mpz_clear(y);
        mpz_clear(x);
    }

    result = _asn1_read_mpz_from_octet_string(p, pubkey_asn1, "h.cwa.p");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(a, pubkey_asn1, "h.cwa.a");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(b, pubkey_asn1, "h.cwa.b");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("cwa.p parsed as : %Zd (0x%Zx)\n", p, p);
    //gmp_printf("cwa.a parsed as : %Zd (0x%Zx)\n", a, a);
    //gmp_printf("cwa.b parsed as : %Zd (0x%Zx)\n", b, b);
    cwHash_set_mpz(cwa, chk->r, p, a, b);

    result = _asn1_read_mpz_from_octet_string(p, pubkey_asn1, "h.cwb.p");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(a, pubkey_asn1, "h.cwb.a");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(b, pubkey_asn1, "h.cwb.b");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("cwb.p parsed as : %Zd (0x%Zx)\n", p, p);
    //gmp_printf("cwb.a parsed as : %Zd (0x%Zx)\n", a, a);
    //gmp_printf("cwb.b parsed as : %Zd (0x%Zx)\n", b, b);
    cwHash_set_mpz(cwb, chk->r, p, a, b);

    icartHash_init(chk->H);
    icartHash_set_param(chk->H, hcv, cwa, cwb);
    sparseTree_init(chk->tree, chk->order, _init_chk_node);
    element_init_G1(e_pt, chk->pairing);
    _CHKPKE_precalc_H0(e_pt, chk);
    element_init_GT(chk->eQH, chk->pairing);
    element_pairing(chk->eQH, chk->Q, e_pt);
    chk->is_secret = false;
    // /printf("init complete\n");

    element_clear(e_pt);
    mpz_clear(b);
    mpz_clear(a);
    mpz_clear(p);
    cwHash_clear(cwb);
    cwHash_clear(cwa);
    mpECurve_clear(hcv);
    asn1_delete_structure(&pubkey_asn1);
    asn1_delete_structure(&CHKPKE_asn1);
    return 0;

error_cleanup2:
    mpz_clear(b);
    mpz_clear(a);
    mpz_clear(p);
    cwHash_clear(cwb);
    cwHash_clear(cwa);
    mpECurve_clear(hcv);
    element_clear(chk->ePQ);
    element_clear(chk->P);
    element_clear(chk->Q);
    pbc_param_clear(chk->param);

error_cleanup1:
    mpz_clear(chk->h);
    mpz_clear(chk->r);
    mpz_clear(chk->q);
    asn1_delete_structure(&pubkey_asn1);
    asn1_delete_structure(&CHKPKE_asn1);
    return -1;
}

int CHKPKE_init_privkey_decode_DER(CHKPKE_t chk, char *der, int sz) {
    ASN1_TYPE CHKPKE_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE privkey_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    char *param_string;
    int result;
    mpECurve_t hcv;
    cwHash_t cwa, cwb;
    mpz_t p, a, b;
    element_t e_pt;
    int qbits;
    //int length;
    //int lwrote;
    //char *buffer;

    result = asn1_array2tree(fspke_asn1_tab, &CHKPKE_asn1, asnError);

    if (result != 0) {
        asn1_perror (result);
        printf ("%s", asnError);
        assert(result == 0);
    }

    // create an empty ASN1 structure
    result = asn1_create_element(CHKPKE_asn1, "ForwardSecurePKE.CHKPrivateKey",
        &privkey_asn1);
    assert(result == 0);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, privkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    result = asn1_der_decoding(&privkey_asn1, der, sz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, privkey_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // Initialize pairing parameter fields
    mpz_init(chk->q);
    mpz_init(chk->r);
    mpz_init(chk->h);

    // Read pairing parameters from ASN1 structure
    result = _asn1_read_mpz_from_octet_string(chk->q, privkey_asn1, "pubkey.params.q");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("q parsed as : %Zd (0x%Zx)\n", chk->q, chk->q);

    result = _asn1_read_mpz_from_octet_string(chk->r, privkey_asn1, "pubkey.params.r");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("r parsed as : %Zd (0x%Zx)\n", chk->r, chk->r);

    result = _asn1_read_mpz_from_octet_string(chk->h, privkey_asn1, "pubkey.params.h");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("h parsed as : %Zd (0x%Zx)\n", chk->h, chk->h);

    result = _asn1_read_int_from_integer(&(chk->p_exp2), privkey_asn1, "pubkey.params.exp2");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("exp2 parsed as : %d (0x%x)\n", chk->p_exp2, chk->p_exp2);

    result = _asn1_read_int_from_integer(&(chk->p_exp1), privkey_asn1, "pubkey.params.exp1");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("exp1 parsed as : %d (0x%x)\n", chk->p_exp1, chk->p_exp1);

    result = _asn1_read_int_from_integer(&(chk->p_sign1), privkey_asn1, "pubkey.params.sign1");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("sign1 parsed as : %d (0x%x)\n", chk->p_sign1, chk->p_sign1);

    result = _asn1_read_int_from_integer(&(chk->p_sign0), privkey_asn1, "pubkey.params.sign0");
    if (result != 0) goto error_cleanup1;
    //gmp_printf("sign0 parsed as : %d (0x%x)\n", chk->p_sign0, chk->p_sign0);

    param_string = _gen_pbc_param_a_string(chk);
    //printf("-----\nParams\n-----\n%s-----\n", param_string);

    result = pbc_param_init_set_str(chk->param, param_string);
    assert(result == 0);
    if (result != 0) goto error_cleanup1;
    free(param_string);

    //printf("init pairing\n");
    pairing_init_pbc_param(chk->pairing, chk->param);
    //printf("init curve\n");
    mpECurve_init(chk->C);
    //printf("setup curve\n");
    qbits = mpz_sizeinbase(chk->q, 2);
    //printf("setup curve qbits = %d\n", qbits);

    element_init_G1(chk->P,chk->pairing);
    element_init_G1(chk->Q,chk->pairing);
    element_init_GT(chk->ePQ,chk->pairing);
    mpECurve_init(hcv);
    cwHash_init(cwa);
    cwHash_init(cwb);
    mpz_init(p);
    mpz_init(a);
    mpz_init(b);

    result = _asn1_read_element_t_from_CurvePoint(chk->P, privkey_asn1, "pubkey.pPt");
    if (result != 0) goto error_cleanup2;
    //element_printf("P: %B\n", chk->P);

    result = _asn1_read_element_t_from_CurvePoint(chk->Q, privkey_asn1, "pubkey.qPt");
    if (result != 0) goto error_cleanup2;
    //element_printf("Q: %B\n", chk->Q);

    element_pairing(chk->ePQ, chk->P, chk->Q);

    _CHKPKE_setup_ECurve(chk, qbits);

    result = _asn1_read_int_from_integer(&(chk->depth), privkey_asn1, "pubkey.depth");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("depth parsed as : %d (0x%x)\n", chk->depth, chk->depth);

    result = _asn1_read_int_from_integer(&(chk->order), privkey_asn1, "pubkey.order");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("order parsed as : %d (0x%x)\n", chk->order, chk->order);

    {
        mpz_t x,y;

        mpz_init(x);
        result = _asn1_read_mpz_from_octet_string(x, privkey_asn1, "pubkey.h.g.x");
        if (result != 0) {
            mpz_clear(x);
            goto error_cleanup2;
        }
        //gmp_printf("g.x parsed as : %Zd (0x%Zx)\n", x, x);

        mpz_init(y);
         result = _asn1_read_mpz_from_octet_string(y, privkey_asn1, "pubkey.h.g.y");
        if (result != 0) {
            mpz_clear(y);
            mpz_clear(x);
            goto error_cleanup2;
        }
        //gmp_printf("g.y parsed as : %Zd (0x%Zx)\n", y, y);

        mpECurve_set_mpz_ws(hcv, chk->q, chk->C->coeff.ws.a->i,
            chk->C->coeff.ws.b->i, chk->r, chk->h, x, y, qbits);

        mpz_clear(y);
        mpz_clear(x);
    }

    result = _asn1_read_mpz_from_octet_string(p, privkey_asn1, "pubkey.h.cwa.p");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(a, privkey_asn1, "pubkey.h.cwa.a");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(b, privkey_asn1, "pubkey.h.cwa.b");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("cwa.p parsed as : %Zd (0x%Zx)\n", p, p);
    //gmp_printf("cwa.a parsed as : %Zd (0x%Zx)\n", a, a);
    //gmp_printf("cwa.b parsed as : %Zd (0x%Zx)\n", b, b);
    cwHash_set_mpz(cwa, chk->r, p, a, b);

    result = _asn1_read_mpz_from_octet_string(p, privkey_asn1, "pubkey.h.cwb.p");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(a, privkey_asn1, "pubkey.h.cwb.a");
    if (result != 0) goto error_cleanup2;
    result = _asn1_read_mpz_from_octet_string(b, privkey_asn1, "pubkey.h.cwb.b");
    if (result != 0) goto error_cleanup2;
    //gmp_printf("cwb.p parsed as : %Zd (0x%Zx)\n", p, p);
    //gmp_printf("cwb.a parsed as : %Zd (0x%Zx)\n", a, a);
    //gmp_printf("cwb.b parsed as : %Zd (0x%Zx)\n", b, b);
    cwHash_set_mpz(cwb, chk->r, p, a, b);

    icartHash_init(chk->H);
    icartHash_set_param(chk->H, hcv, cwa, cwb);
    sparseTree_init(chk->tree, chk->order, _init_chk_node);
    element_init_G1(e_pt, chk->pairing);
    _CHKPKE_precalc_H0(e_pt, chk);
    element_init_GT(chk->eQH, chk->pairing);
    element_pairing(chk->eQH, chk->Q, e_pt);
    chk->is_secret = false;
    //printf("pubkey init complete\n");
    
    {
        int i;
        _chkpke_node_data_t *nd;
        _sparseTree_t *node;
        mpECP_t ecp_pt;

        mpECP_init(ecp_pt);
        i = 1;
        while (true) {
            char abuffer[80];
            int j, depth;
            int64_t ordinal;

            sprintf(abuffer, "secrets.?%d.id.depth", i);
            result = _asn1_read_int_from_integer(&depth, privkey_asn1, abuffer);
            if (result != 0) break;
            //gmp_printf("secret %d depth parsed as : %d (0x%x)\n", i, depth, depth);

            sprintf(abuffer, "secrets.?%d.id.ordinal", i);
            result = _asn1_read_int64_from_integer(&ordinal, privkey_asn1, abuffer);
            // TODO: remove this assert
            assert(result == 0);
            if (result != 0) {
                mpECP_clear(ecp_pt);
                goto error_cleanup3;
            }
            //gmp_printf("secret %d ordinal parsed as : %ld (0x%x)\n", i, ordinal, ordinal);

            node = sparseTree_find_by_address(chk->tree, depth, ordinal);
            nd = node->nodeData;

            // should be starting with an empty node
            assert(nd->S == NULL);
            assert(nd->R == NULL);
            assert(nd->nR == 0);

            nd->S = (element_ptr)malloc(sizeof(element_t));
            if (depth > 0) {
                nd->R = (element_ptr)malloc(depth * sizeof(element_t));
            }
            nd->nR = depth;

            sprintf(abuffer, "secrets.?%d.s", i);
            result = _asn1_read_mpECP_from_octet_string(ecp_pt, privkey_asn1, abuffer, chk->C);
            // TODO: remove this assert
            assert(result == 0);
            if (result != 0) {
                mpECP_clear(ecp_pt);
                goto error_cleanup3;
            }
            element_init_G1(nd->S, chk->pairing);
            _pbc_element_set_mpECP(nd->S, ecp_pt, chk->pairing);

            for (j = 0; j < depth; j++) {
                sprintf(abuffer, "secrets.?%d.r.?%d", i, j + 1);
                result = _asn1_read_mpECP_from_octet_string(ecp_pt, privkey_asn1, abuffer, chk->C);
                // TODO: remove this assert
                assert(result == 0);
                if (result != 0) {
                    mpECP_clear(ecp_pt);
                    goto error_cleanup3;
                }
                element_init_G1(&(nd->R[j]), chk->pairing);
                _pbc_element_set_mpECP(&(nd->R[j]), ecp_pt, chk->pairing);
            }

            i += 1;
        }
        
        mpECP_clear(ecp_pt);

        // if no secrets read that's an error
        if (i == 1) goto error_cleanup3;
    }

    element_clear(e_pt);
    mpz_clear(b);
    mpz_clear(a);
    mpz_clear(p);
    cwHash_clear(cwb);
    cwHash_clear(cwa);
    mpECurve_clear(hcv);
    asn1_delete_structure(&privkey_asn1);
    asn1_delete_structure(&CHKPKE_asn1);
    return 0;

error_cleanup3:
    element_clear(chk->eQH);
    sparseTree_clear(chk->tree);
    icartHash_clear(chk->H);

error_cleanup2:
    mpz_clear(b);
    mpz_clear(a);
    mpz_clear(p);
    cwHash_clear(cwb);
    cwHash_clear(cwa);
    mpECurve_clear(hcv);
    element_clear(chk->ePQ);
    element_clear(chk->P);
    element_clear(chk->Q);
    pbc_param_clear(chk->param);

error_cleanup1:
    mpz_clear(chk->h);
    mpz_clear(chk->r);
    mpz_clear(chk->q);
    asn1_delete_structure(&privkey_asn1);
    asn1_delete_structure(&CHKPKE_asn1);
    return -1;
}

char *CHKPKE_Enc_DER(CHKPKE_t chk, element_t plain, int64_t interval, int *sz) {
    ASN1_TYPE CHKPKE_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE ciphertext_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    sparseTree_ptr_t node;
    sparseTree_ptr_t pathnode;
    element_t lambda;
    element_t lambdaP;
    element_t d;
    element_t Md;
    element_ptr ePtr;
    mpECP_t ecp_pt;
    mpz_t id;
    mpz_t lambda_mpz;
    int depth;
    int sum, length;
    int result;
    char *buffer;

    sum = 0;

    result = asn1_array2tree(fspke_asn1_tab, &CHKPKE_asn1, asnError);

    if (result != 0) {
        asn1_perror (result);
        printf ("%s", asnError);
        assert(result == 0);
    }

    // create an empty ASN1 structure
    result = asn1_create_element(CHKPKE_asn1, "ForwardSecurePKE.CHKCiphertext",
        &ciphertext_asn1);
    assert(result == 0);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, ciphertext_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    mpECP_init(ecp_pt);
    element_init_Zr(lambda, chk->pairing);
    element_init_G1(lambdaP, chk->pairing);
    element_init_GT(d, chk->pairing);
    element_init_GT(Md, chk->pairing);
    mpz_init(id);
    mpz_init(lambda_mpz);

    // pbc pulls random values from /dev/urandom
    element_random(lambda);
    element_to_mpz(lambda_mpz, lambda);

    result = asn1_write_value (ciphertext_asn1, "u", "NEW", 1);
    assert(result == 0);
    element_mul_zn(lambdaP, chk->P, lambda);
    _mpECP_set_pbc_element(ecp_pt, lambdaP, chk->C);
    sum += _asn1_write_mpECP_as_octet_string(ciphertext_asn1, "u.?LAST", ecp_pt);

    node = sparseTree_find_by_address(chk->tree, chk->depth, interval);

    for (depth = 1; depth <= chk->depth ; depth++) {

        pathnode = node;
        while (pathnode->depth > depth) {
            pathnode = pathnode->parent;
        }

        //printf("writing l*H for node (%d, %ld)\n", pathnode->depth, pathnode->ordinal);

        _mpz_set_ull(id, sparseTree_node_id(pathnode));
        icartHash_hashval(ecp_pt, chk->H, id);
        mpECP_scalar_mul_mpz(ecp_pt, ecp_pt, lambda_mpz);
        // Add a field to the SEQUENCE OF
        result = asn1_write_value (ciphertext_asn1, "u", "NEW", 1);
        assert(result == 0);
        sum += _asn1_write_mpECP_as_octet_string(ciphertext_asn1, "u.?LAST", ecp_pt);
    }

    element_pow_mpz(d, chk->eQH, lambda_mpz);
    element_mul(Md , plain, d);

    ePtr = element_x(Md);
    element_to_mpz(lambda_mpz, ePtr);
    sum += _asn1_write_mpz_as_octet_string(ciphertext_asn1, "v.x", lambda_mpz);

    ePtr = element_y(Md);
    element_to_mpz(lambda_mpz, ePtr);
    sum += _asn1_write_mpz_as_octet_string(ciphertext_asn1, "v.y", lambda_mpz);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, ciphertext_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // validate export
    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (char *)malloc((sum) * sizeof(char));
    result = asn1_der_coding(ciphertext_asn1, "", buffer, &length, asnError);
    assert(result == 0);
    assert(length < sum);
    *sz = length;

    mpz_clear(lambda_mpz);
    mpz_clear(id);
    element_clear(Md);
    element_clear(d);
    element_clear(lambdaP);
    element_clear(lambda);
    mpECP_clear(ecp_pt);
    asn1_delete_structure(&ciphertext_asn1);
    asn1_delete_structure(&CHKPKE_asn1);

    return buffer;
}

static int _asn1_read_element_gt_from_xy(element_t value, asn1_node root, char *attribute) {
    int result, length, lread, len, len_element;
    char *buffer, *abuffer;

    len = strlen(attribute) + 5;
    abuffer = (char *)malloc((len + 1)*sizeof(char));

    // call read_value with NULL buffer to get length
    strncpy(abuffer, attribute, len);
    strncat(abuffer, ".x", 5);
    length = 0;
    result = asn1_read_value(root, abuffer, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    // allocate
    len_element = element_length_in_bytes(value) >> 1;
    //printf("length string = %d, length element expected = %d\n", length, len_element);
    assert(len_element >= length);
    //printf("allocating space for 2x %d-bit x,y values\n", (length * 8));
    buffer = (char *)malloc(((len_element * 2) + 1)*sizeof(char));
    bzero(buffer, len_element * 2);

    lread = length + 1;
    result = asn1_read_value(root, abuffer, &buffer[len_element-length], &lread);
    if (result != ASN1_SUCCESS) return -1;
    //printf("read X\n");
    //assert(result == 0);
    if (lread != length) return -1;
    //assert(lread == length);
    //{
    //    int i;
    //    printf("read X (%s) as :", abuffer);
    //    for (i = 0; i < len_element; i++) {
    //        printf("%02X", (unsigned char)buffer[i]);
    //    }
    //    printf("\n");
    //}

    strncpy(abuffer, attribute, len);
    strncat(abuffer, ".y", 5);
    length = 0;
    result = asn1_read_value(root, abuffer, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    assert(len_element >= length);
    lread = length + 1;
    result = asn1_read_value(root, abuffer, &buffer[(2*len_element)-length], &lread);
    if (result != ASN1_SUCCESS) return -1;
    //printf("read Y\n");
    //assert(result == 0);
    if (lread != length) return -1;
    //assert(lread == length);
    //{
    //    int i;
    //    printf("read Y (%s) as :", abuffer);
    //    for (i = 0; i < len_element; i++) {
    //        printf("%02X", (unsigned char)buffer[i+length]);
    //    }
    //    printf("\n");
    //}

    element_from_bytes(value, (unsigned char*)buffer);
    //element_printf("GT: %B\n", value);
    free(buffer);
    free(abuffer);
    return 0;
}

int CHKPKE_Dec_DER(element_t plain, CHKPKE_t chk, char *cipher, int sz, int64_t interval) {
    ASN1_TYPE CHKPKE_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE ciphertext_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int i, result;
    sparseTree_ptr_t node;
    _chkpke_node_data_t *nd;
    char abuffer[80];
    mpz_t rmin1, x, y;

    mpECP_t ecp_pt;
    element_t e_pt, e_gt, eU0Sw, pi;

    // ensure we can derive the secrets for the chosen interval
    result = CHKPKE_Der(chk, interval);
    if (result != 0) return -1;

    // validate that we have the expected secret material
    node = sparseTree_find_by_address(chk->tree, chk->depth, interval);
    nd = (_chkpke_node_data_t *)node->nodeData;
    assert(nd->S != NULL);
    assert(nd->R != NULL);
    assert(nd->nR == chk->depth);

    result = asn1_array2tree(fspke_asn1_tab, &CHKPKE_asn1, asnError);

    if (result != 0) {
        asn1_perror (result);
        printf ("%s", asnError);
        assert(result == 0);
    }

    // create an empty ASN1 structure
    result = asn1_create_element(CHKPKE_asn1, "ForwardSecurePKE.CHKCiphertext",
        &ciphertext_asn1);
    assert(result == 0);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, ciphertext_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    result = asn1_der_decoding(&ciphertext_asn1, cipher, sz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, ciphertext_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    mpECP_init(ecp_pt);
    element_init_G1(e_pt, chk->pairing);
    element_init_GT(e_gt, chk->pairing);
    element_init_GT(eU0Sw, chk->pairing);
    element_init_GT(pi, chk->pairing);
    mpz_init(rmin1);
    mpz_init(x);
    mpz_init(y);

    //printf("read U0\n");
    result = _asn1_read_mpECP_from_octet_string(ecp_pt, ciphertext_asn1, "u.?1", chk->C);
    if (result != 0) goto error_cleanup1;
    _pbc_element_set_mpECP(e_pt, ecp_pt, chk->pairing);

    //("calc pairing eU0Sw\n");
    // caluclate e(U0, Sw), where U0 = lambda * P
    element_pairing(eU0Sw, e_pt, nd->S);

    //printf("read U1\n");
    result = _asn1_read_mpECP_from_octet_string(ecp_pt, ciphertext_asn1, "u.?2", chk->C);
    if (result != 0) goto error_cleanup1;
    _pbc_element_set_mpECP(e_pt, ecp_pt, chk->pairing);

    // calculate product PI(e(Rwi-1, Ui), where Ui = lHwi
    element_pairing(pi, &(nd->R[0]), e_pt);
    for (i = 2; i <= chk->depth; i++) {
        sprintf(abuffer, "u.?%d", i+1);
        //printf("read U%d\n", i);
        result = _asn1_read_mpECP_from_octet_string(ecp_pt, ciphertext_asn1, abuffer, chk->C);
        if (result != 0) goto error_cleanup1;
        _pbc_element_set_mpECP(e_pt, ecp_pt, chk->pairing);

        element_pairing(e_gt, &(nd->R[i-1]), e_pt);
        element_mul(pi, pi, e_gt);
    }

    //printf("invert pi\n");
    // invert numerator term
    mpz_sub_ui(rmin1, chk->r, 1);
    element_pow_mpz(eU0Sw, eU0Sw, rmin1);

    //printf("mul eU0Sw * pi**-1\n");
    // d = e(U0, Sw) / PI() = e(U0, Sw) * PI() ** (r-1)
    // d ** -1 = e(U0, Sw) ** -1 * PI()
    element_mul(eU0Sw, eU0Sw, pi);

    //printf("read V (M * d)\n");
    // V = M*d
    result = _asn1_read_element_gt_from_xy(e_gt, ciphertext_asn1, "v");
    if (result != 0) goto error_cleanup1;

    //printf("and... dismount\n");
    // decrypt M = V * d**-1 = = V / d = V / ( eU0Sw / PI_i=1..n(Rwi-1, Ui) )
    element_mul(plain, e_gt, eU0Sw);

    mpz_clear(y);
    mpz_clear(x);
    mpz_clear(rmin1);
    element_clear(pi);
    element_clear(eU0Sw);
    element_clear(e_gt);
    element_clear(e_pt);
    mpECP_clear(ecp_pt);

    return 0;

error_cleanup1:
    mpz_clear(y);
    mpz_clear(x);
    mpz_clear(rmin1);
    element_clear(pi);
    element_clear(eU0Sw);
    element_clear(e_gt);
    element_clear(e_pt);
    mpECP_clear(ecp_pt);
    return -1;
}
