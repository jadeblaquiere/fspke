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
#include <limits.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>

static int64_t _expi(uint64_t i, uint64_t j){
    // limit recursion
    assert(j < 32);
    assert(j > 0);
    if (j == 1) return i;
    return i * _expi(i, j - 1);
}

int main(int argc, char **argv) {
    int depth = 6;
    int order = 16;
    int qbits = 512;
    int rbits = 384;
    int64_t intervals;
    poptContext pc;
    struct poptOption po[] = {
        {"depth", 'd', POPT_ARG_INT, &depth, 6, "number of branches in the BTE btree, default = 6", "tree depth"},
        {"order", 'o', POPT_ARG_INT, &order, 16, "order of nodes (number of subnodes per node) in BTE btree, default = 16", "tree order"},
        {"qbits", 'q', POPT_ARG_INT, &qbits, 512, "target number of bits in primary fields (p of Fp, Fp2), default = 512", "bits in Fp"},
        {"rbits", 'r', POPT_ARG_INT, &rbits, 384, "target number of bits for prime group order r, default = 384", "bit order of EC groups"},
        POPT_AUTOHELP
        {NULL}
    };
    CHKPKE_t pke;
    char *der;
    int sz;
    int result;

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
    
    if (qbits < (rbits + 8)) {
        printf("<ValueError>: qbits must be >= rbits + 8\n");
        exit(1);
    }
    
    // practical limit on intervals - should fit in signed integer
    intervals = _expi(order, depth);
    if (intervals > INT_MAX) {
        printf("<ValueError>: order ** depth must be <= 2**31 - 1\n");
        exit(1);
    }

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options
    CHKPKE_init_Gen(pke, qbits, rbits, depth, order);

     //printf("exporting key\n");
    der = CHKPKE_privkey_encode_DER(pke, 0, &sz);
    assert(der != NULL);

    result = write_b64wrapped_to_file(stdout, der, sz, "CHK PRIVATE KEY");
    if (result != 0) {
        fprintf(stderr, "<WriteError>: Error writing output\n");
        exit(1);
    }

    free(der);
    CHKPKE_clear(pke);

    return 0;
}
