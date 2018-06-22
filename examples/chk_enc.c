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
#include <libtasn1.h>
#include <limits.h>
#include <popt.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _readbuf {
    char    buffer[16000];
    struct _readbuf *next;
    int     sz;
} _readbuf_t;

static void _free_readbuf(_readbuf_t *next) {
    if (next->next != NULL) _free_readbuf(next->next);
    free(next);
    return;
}

extern const asn1_static_node chk_example_asn1_tab[];

int main(int argc, char **argv) {
    char *filename = NULL;
    char *keyfilename = NULL;
    unsigned char *msg;
    unsigned char *ctext;
    unsigned long long clen;
    size_t msglen;
    int interval = 0;
    FILE *fPtr = stdin;
    FILE *kPtr = NULL;
    poptContext pc;
    struct poptOption po[] = {
        {"file", 'f', POPT_ARG_STRING, &filename, 0, "read input from filepath instead of stdin", "file path"},
        {"key", 'k', POPT_ARG_STRING, &keyfilename, 0, "PUBLIC key file path", "public key"},
        {"interval", 'i', POPT_ARG_INT, &interval, 0, "set interval for output key, default = 0", "interval"},
        POPT_AUTOHELP
        {NULL}
    };
    CHKPKE_t pke;
    char *der;
    int sz, bufsz, result;
    element_t shared_element;
    unsigned char shared_hash[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

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
        fprintf(stderr,"<Error>: Must provide PUBLIC key file via --key=<key path> or -k <key path>\n");
        exit(1);
    }
    kPtr = fopen(keyfilename, "r");
    if (kPtr == NULL) {
        fprintf(stderr,"<Error>: Unable to open PUBLIC key file %s\n", filename);
        exit(1);
    }

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options

    // This example is a little complicated as we are combining CHK-based 
    // public key encryption for key exchange (kex) with symmetric encryption
    // to encode an arbitrary length input.

    // read key in ASN1 DER format from key file
    der = read_b64wrapped_from_file(kPtr, "CHK PUBLIC KEY", &sz);
    if (der == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 PUBLIC KEY data\n");
        exit(1);
    }

    // import/decode pubkey
    result = CHKPKE_init_pubkey_decode_DER(pke, der, sz);
    if (result != 0) {
        fprintf(stderr, "<ParseError>: Unable to parse input as DER-encoded public key");
        exit(1);
    }
    free(der);

    // read entire plaintext input into memory
    {
        size_t len, rlen;
        _readbuf_t *head;
        _readbuf_t *next;
        unsigned char *buf;

        // read file into linked list of chunks
        head = (_readbuf_t *)malloc(sizeof(_readbuf_t));
        next = head;
        next->next = (_readbuf_t *)NULL;
        len = 0;

        while(true) {
            rlen = fread(next->buffer, sizeof(char), 16000, fPtr);
            len += rlen;
            next->sz = rlen;
            if (feof(fPtr)) {
                break;
            }
            next->next = (_readbuf_t *)malloc(sizeof(_readbuf_t));
            next = next->next;
            next->next = NULL;
        }
        if (len == 0) {
            fprintf(stderr,"<Error>: plaintext input zero length");
            exit(1);
        }

        // concatenate chunks into a single buffer
        msg = (unsigned char *)malloc((len + 1) * sizeof(char));
        next = head;
        buf = msg;
        while (next != NULL) {
            bcopy(next->buffer, buf, next->sz);
            buf += next->sz;
            next = next->next;
        }
        msg[len] = 0;
        msglen = len;
        _free_readbuf(head);
    }

    // generate a shared (random) key;
    CHKPKE_init_random_element(shared_element, pke);

    // encrypt shared (random) key for recipient, interval
    der = CHKPKE_Enc_DER(pke, shared_element, interval, &sz);

    // hash shared key to get a 256-bit key for encryption w/ChaCha
    {
        int len = 0;
        unsigned char *e_bytes;
        e_bytes = CHKPKE_element_to_bytes(shared_element, &len);

        crypto_hash_sha256(shared_hash, e_bytes, len);
        free (e_bytes);
    }

    // allocate sufficient buffer for ciphertext;
    clen = msglen + crypto_aead_chacha20poly1305_ietf_ABYTES;
    ctext = (unsigned char *)malloc(clen * sizeof(char));

    // select a random nonce
    randombytes_buf(nonce, sizeof(nonce));

    // paranoid assertions... nonce 64 bits, hashed key 256 bits
    assert(sizeof(nonce) == 12);
    assert(sizeof(shared_hash) == 32);
    assert(der != NULL);
    assert(sz > 0);
    assert(msg != NULL);
    assert(msglen > 0);

    // encode encrypted shared secret and ciphertext+mac combo into 
    // a single ASN1 DER stream
    {
        ASN1_TYPE example_asn1 = ASN1_TYPE_EMPTY;
        ASN1_TYPE message_asn1 = ASN1_TYPE_EMPTY;
        char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
        char interval_string[80];

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

        // key exchange via CHK-encoded element
        result = asn1_write_value(message_asn1, "ad.enckey", der, sz);
        assert(result == 0);

        // key exchange via CHK-encoded element
        result = asn1_write_value(message_asn1, "ad.nonce", nonce, sizeof(nonce));
        assert(result == 0);

        // interval for encryption
        sprintf(interval_string,"%d", interval);
        result = asn1_write_value(message_asn1, "ad.interval", interval_string, 0);
        assert(result == 0);

        // dump additional data in DER format
        free(der);
        sz += clen + 256;
        bufsz = sz;
        der = (char *)malloc((sz) * sizeof(char));
        result = asn1_der_coding(message_asn1, "ad", der, &sz, asnError);
        assert(result == 0);
        assert(sz < bufsz);

        // AEAD symmetric encryption with shared key, MAC covers both message and
        // additional data (encrypted shared key (in der), nonce, interval).
        result = crypto_aead_chacha20poly1305_ietf_encrypt(ctext, &clen, msg,
            msglen, (unsigned char *)der, sz, NULL, nonce, shared_hash);
        assert(result == 0);

        // ciphertext of input message
        result = asn1_write_value(message_asn1, "ctext", ctext, clen);
        assert(result == 0);

        //printf("-----------------\n");
        //asn1_print_structure(stdout, message_asn1, "", ASN1_PRINT_ALL);
        //printf("-----------------\n");

        // encode the entire message
        sz = bufsz;
        result = asn1_der_coding(message_asn1, "", der, &sz, asnError);
        assert(result == 0);
        assert(sz < bufsz);

        asn1_delete_structure(&message_asn1);
        asn1_delete_structure(&example_asn1);
    }

    result = write_b64wrapped_to_file(stdout, der, sz, "CHK ENCRYPTED MESSAGE");
    if (result != 0) {
        fprintf(stderr, "<WriteError>: Error writing output\n");
        exit(1);
    }

    free(ctext);
    free(der);
    CHKPKE_clear(pke);

    return 0;
}
