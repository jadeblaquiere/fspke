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

#ifndef _SPARSETREE_H_INCLUDED_
#define _SPARSETREE_H_INCLUDED_

#include <ecc.h>
#include <gmp.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// sparseTree implements an Order N B-Tree with lazy allocation where
// all non-leaf nodes have exactly N children. Nodes are created when first
// referenced. Supports arbitrary depth. The init parameter provides a
// callback function which is called for each allocated node to initialize
// local data at the node. In this way SimpleNTree can be used to manage a
// tree of data without creating a derived class. Application-specific data
// can be attached to nodeData and the clear function will be called as part
// of the cleanup process so any dynamially allocated data referenced by
// nodeData should be free'd by the clear callback

typedef struct _sparseTree_t {
    int n;
    int depth;
    uint64_t ordinal;
    uint64_t id;
    struct _sparseTree_t *parent;
    struct _sparseTree_t **child;
    void (*init)(struct _sparseTree_t *);
    void (*clear)(struct _sparseTree_t *);
    void *nodeData;
} _sparseTree_t;

typedef _sparseTree_t sparseTree_t[1];
typedef _sparseTree_t *sparseTree_ptr;

void sparseTree_init(sparseTree_t node, int n, void (*init)(_sparseTree_t *));
void sparseTree_clear(sparseTree_t node);

_sparseTree_t *sparseTree_find_by_address(sparseTree_t node, int depth, uint64_t ordinal);

uint64_t sparseTree_node_id(sparseTree_t node);

#ifdef __cplusplus
}
#endif

#endif // _SPARSETREE_H_INCLUDED_
