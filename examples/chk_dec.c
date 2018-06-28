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
#include <b64file.h>
#include <check.h>
#include <fspke.h>
#include <portable_endian.h>
#include <libtasn1.h>
#include <limits.h>
#include <popt.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

extern const asn1_static_node chk_example_asn1_tab[];

unsigned char *_read_asn_octet_string_to_buffer(ASN1_TYPE root, const char *name, int *len) {
    unsigned char *buffer;
    int result;
    int len_test;
    int len_read;

    len_test = 0;
    result = asn1_read_value(root, name, NULL, &len_test);
    assert(result == ASN1_MEM_ERROR);
    assert(len_test > 0);
    buffer = (unsigned char *)malloc((len_test + 1)*sizeof(char));

    len_read = len_test + 1;
    result = asn1_read_value(root, name, buffer, &len_read);
    assert(len_read == len_test);
    *len = len_read;
    buffer[len_read] = 0;
    return buffer;
}

static int _asn1_read_int_from_integer(int *value, asn1_node root, char *attribute) {
    int result, length, lread;
    uint32_t uvalue = 0;
    //char *buffer;

    assert(sizeof(int) == 4);
    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    assert(result == ASN1_MEM_ERROR);
    assert(length > 0);
    assert(length <= sizeof(int));
    lread = sizeof(int);
    result = asn1_read_value(root, attribute, &uvalue, &lread);
    assert(result == ASN1_SUCCESS);
    assert(lread == length);
    *value = (int)be32toh(uvalue);
    //printf("value = 0x%08X", *value);
    if (length < sizeof(int)) {
        *value >>= ((sizeof(int) - length) * 8) ;
    }
    //printf("adjusted value = %d\n", *value);
    return 0;
}

int main(int argc, char **argv) {
    char *filename = NULL;
    char *keyfilename = NULL;
    int interval = 0;
    FILE *fPtr = stdin;
    FILE *kPtr = NULL;
    poptContext pc;
    struct poptOption po[] = {
        {"file", 'f', POPT_ARG_STRING, &filename, 0, "read input from filepath instead of stdin", "file path"},
        {"key", 'k', POPT_ARG_STRING, &keyfilename, 0, "PUBLIC key file path", "public key"},
        POPT_AUTOHELP
        {NULL}
    };
    CHKPKE_t pke;
    unsigned char *der;
    size_t sz; 
    int result;
    element_t shared_element;
    unsigned char shared_hash[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char *kex_bytes, *ctext_bytes, *plain_bytes, *nonce_bytes;
    int kex_sz, ctext_sz, nonce_sz;
    unsigned long long plain_sz;

    // attach gmp realloc/free functions to clear memory before free
    _enable_gmp_safe_clean();

    // pc is the context for all popt-related functions
    pc = poptGetContext(NULL, argc, (const char **)argv, po, 0);
    //poptSetOtherOptionHelp(pc, "[ARG...]");

    {
        // process options and handle each val returned
        int val;
        while ((val = poptGetNextOpt(pc)) >= 0) {
        //printf("poptGetNextOpt returned val %d\n", val);
        }
        if (val != -1) {
            fprintf(stderr,"<Error processing args>\n");
            poptPrintUsage(pc, stderr, 0);
            exit(1);
        }
    }

    if (filename != NULL) {
        fPtr = fopen(filename, "r");
        if (fPtr == NULL) {
            fprintf(stderr,"<Error>: Unable to open input file %s\n", filename);
            exit(1);
        }
    }
    
    if (keyfilename == NULL) {
        fprintf(stderr,"<Error>: Must provide PRIVATE key file via --key=<key path> or -k <key path>\n");
        exit(1);
    }
    kPtr = fopen(keyfilename, "r");
    if (kPtr == NULL) {
        fprintf(stderr,"<Error>: Unable to open PRIVATE key file %s\n", filename);
        exit(1);
    }

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options

    // This example is a little complicated as we are combining CHK-based 
    // public key encryption for key exchange (kex) with symmetric encryption
    // to encode an arbitrary length input.

    // read key in ASN1 DER format from key file
    der = read_b64wrapped_from_file(kPtr, "CHK PRIVATE KEY", &sz);
    if (der == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 PRIVATE KEY data\n");
        exit(1);
    }

    // import/decode pubkey
    result = CHKPKE_init_privkey_decode_DER(pke, der, sz);
    if (result != 0) {
        fprintf(stderr, "<ParseError>: Unable to parse input as DER-encoded private key");
        exit(1);
    }
    free(der);

    // read entire b64 coded message (kex+interval+ciphertext-w/mac) into mem
    
    der = read_b64wrapped_from_file(fPtr, "CHK ENCRYPTED MESSAGE", &sz);
    if (der == NULL) {
        fprintf(stderr,"<Error>: Unable to extract b64 message from input\n");
        exit(1);
    }
    assert(sz > 0);

    // extract encrypted shared secret and ciphertext+mac combo into 
    // a single ASN1 DER stream
    {
        ASN1_TYPE example_asn1 = ASN1_TYPE_EMPTY;
        ASN1_TYPE message_asn1 = ASN1_TYPE_EMPTY;
        char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

        // read ASN1 syntax
        result = asn1_array2tree(chk_example_asn1_tab, &example_asn1, asnError);

        if (result != 0) {
            asn1_perror (result);
            printf ("%s", asnError);
            assert(result == 0);
        }

        // create an empty ASN1 message structure
        result = asn1_create_element(example_asn1, "ExampleMessageFormat.Message",
            &message_asn1);
        assert(result == 0);

        //printf("-----------------\n");
        //asn1_print_structure(stdout, message_asn1, "", ASN1_PRINT_ALL);
        //printf("-----------------\n");

        // read DER into ASN1 structure
        {
            int isz = (int)sz;
            result = asn1_der_decoding(&message_asn1, der, isz, asnError);
        }
        if (result != ASN1_SUCCESS) return -1;

        //printf("-----------------\n");
        //asn1_print_structure(stdout, message_asn1, "", ASN1_PRINT_ALL);
        //printf("-----------------\n");

        // dump additional data in DER format
        kex_sz = sz;
        {
            int isz;
            isz = (int)sz;
            result = asn1_der_coding(message_asn1, "ad", der, &isz, asnError);
            sz = isz;
        }
        assert(result == 0);
        assert(sz < kex_sz);

        kex_bytes = _read_asn_octet_string_to_buffer(message_asn1, "ad.enckey", &kex_sz);
        assert(kex_bytes != NULL);
        nonce_bytes = _read_asn_octet_string_to_buffer(message_asn1, "ad.nonce", &nonce_sz);
        assert(nonce_bytes != NULL);
        result = _asn1_read_int_from_integer(&interval, message_asn1, "ad.interval");
        assert(result == 0);
        ctext_bytes = _read_asn_octet_string_to_buffer(message_asn1, "ctext", &ctext_sz);
        assert(ctext_bytes != NULL);

        asn1_delete_structure(&message_asn1);
        asn1_delete_structure(&example_asn1);
    }

    CHKPKE_init_element(shared_element, pke);
    result =  CHKPKE_Dec_DER(shared_element, pke, kex_bytes, kex_sz, interval);
    if (result != 0) {
        fprintf(stderr, "<Error>: Error deriving shared key for interval\n");
        exit(1);
    }

    // hash shared key to get a 256-bit key for encryption w/XChaCha
    {
        size_t len = 0;
        unsigned char *e_bytes;
        e_bytes = CHKPKE_element_to_bytes(shared_element, &len);

        crypto_hash_sha256(shared_hash, e_bytes, len);
        free (e_bytes);
    }

    // plaintext is shorter than ciphertext, allocate buffer for decryption
    plain_sz = ctext_sz;
    plain_bytes = (unsigned char *)malloc(plain_sz * sizeof(char));
    
    // paranoid assertions... nonce 64 bits, hashed key 256 bits
    assert(sizeof(nonce_bytes) == 8);
    assert(sizeof(shared_hash) == 32);
    assert(kex_bytes != NULL);
    assert(kex_sz > 0);
    assert(ctext_bytes != NULL);
    assert(ctext_sz > 0);

    // decrypt and authenticate MAC for message
    result = crypto_aead_chacha20poly1305_ietf_decrypt(plain_bytes, &plain_sz,
        NULL, ctext_bytes, ctext_sz, (unsigned char *)der, sz, nonce_bytes, shared_hash);
    assert(result == 0);
    assert(plain_sz > 0);
    assert(plain_sz < ctext_sz);
    plain_bytes[plain_sz] = 0;

    printf("%s", plain_bytes);

    CHKPKE_element_clear(shared_element);
    free(plain_bytes);
    free(nonce_bytes);
    free(kex_bytes);
    free(ctext_bytes);
    CHKPKE_clear(pke);

    return 0;
}
