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
#include <fspke/sparsetree.h>
#include <stdint.h>
//#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// recursive algorithm to sum the number of nodes in previous rows
// finite sequence is 1 + n + n**2 + .. n**k
// (it is assumed that the number of nodes is less than 2**64)
static uint64_t _recurse_prev_rows(int n, int k) {
    if (k == 0) return 1;
    return (1 + (n * _recurse_prev_rows(n,k-1)));
}

static uint64_t _calc_prev_rows(int n, int k) {
    return _recurse_prev_rows(n, k-1);
}

void sparseTree_init(sparseTree_t node, int n, void (*init)(_sparseTree_t *)) {
    int i;
    node->n = n;
    node->parent = NULL;
    node->depth = 0;
    node->ordinal = 0;
    node->id = 0;
    node->child = (_sparseTree_t **)malloc(n * sizeof(_sparseTree_t *));
    for (i = 0; i < n; i++) {
        node->child[i] = (_sparseTree_t *)NULL;
    }
    node->init = init;
    node->clear = NULL;
    node->nodeData = NULL;
    if (node->init != NULL) node->init(node);
    return;
}

static void _sparseTree_init_child(sparseTree_t node, _sparseTree_t *parent, uint64_t ordinal) {
    int i;
    //printf("initializing child (%d, %d) of (%d, %d)\n", parent->depth + 1, ordinal, parent->depth, parent->ordinal);
    node->n = parent->n;
    node->parent = parent;
    node->depth = parent->depth + 1;
    node->ordinal = (parent->n * parent->ordinal) + ordinal;
    node->id = _calc_prev_rows(node->n, node->depth) + node->ordinal;
    node->child = (_sparseTree_t **)malloc(node->n * sizeof(_sparseTree_t *));
    for (i = 0; i < node->n; i++) {
        node->child[i] = (_sparseTree_t *)NULL;
    }
    node->init = parent->init;
    node->clear = NULL;
    node->nodeData = NULL;
    //printf("calling node init if present\n");
    if (node->init != NULL) node->init(node);
    return;
}

static _sparseTree_t *_sparseTree_nth_child(sparseTree_t node, int n) {
    //printf("looking for child %d of (%d, %d)\n", n, node->depth, node->ordinal);
    assert(n >= 0);
    assert(n < node->n);
    if (node->child[n] != NULL) {
        return node->child[n];
    } else {
        //printf("creating child\n");
        // if doesn't exist we create when referenced (lazy allocation)
        node->child[n] = (_sparseTree_t *)malloc(sizeof(_sparseTree_t));
        //printf("calling init child\n");
        _sparseTree_init_child(node->child[n], node, n);
        //printf("returning child\n");
        return node->child[n];
    }
}

void sparseTree_clear(sparseTree_t node) {
    int i;
    for (i = 0; i < node->n; i++) {
        if (node->child[i] != NULL) {
            sparseTree_clear(node->child[i]);
        }
        free(node->child[i]);
        node->child[i] = NULL;
    }
    if (node->clear != NULL) node->clear(node);
#ifdef  SAFE_CLEAN
    memset((void *)(node->child), 0, sizeof(*(node->child)));
#endif
    free(node->child);
    node->init = NULL;
    node->clear = NULL;
    node->nodeData = NULL;
#ifdef  SAFE_CLEAN
    memset((void *)(node), 0, sizeof(*node));
#endif
    return;
}

static uint64_t _expi(uint64_t i, uint64_t j) {
    if (j < 1) return 1;
    return i * _expi(i, j - 1);
}

_sparseTree_t *sparseTree_find_by_address(sparseTree_t node, int depth, uint64_t ordinal) {
    int path;
    //printf("sparsetree: trying to find ordinal = %ld from (%d, %ld) + %d\n", ordinal, node->depth, node->ordinal, depth);
    if (depth == 0) {
        assert(node->ordinal == ordinal);
        return node;
    }
    path = (ordinal / _expi(node->n, depth-1)) % (node->n);
    return sparseTree_find_by_address(_sparseTree_nth_child(node, path), depth-1, ordinal);
}

uint64_t sparseTree_node_id(sparseTree_t node) {
    return node->id;
}
