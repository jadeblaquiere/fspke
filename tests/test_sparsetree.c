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
#include <check.h>
#include <fspke/sparsetree.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned int _hashfunc(int x) {
    return ((((unsigned int)x * 4737) + 3154) % 16369) % 251;
}

typedef struct {
    unsigned int hd;
    unsigned int ho;
} _nodeHash_t;

static int allocated_nodes = 0;

void _clear_node(_sparseTree_t *node) {
    _nodeHash_t *nd;
    assert(node->nodeData != NULL);
    nd = (_nodeHash_t *)node->nodeData;
    assert(nd->hd == _hashfunc(node->depth));
    assert(nd->ho == _hashfunc(node->ordinal));
    free(node->nodeData);
    allocated_nodes--;
}

void _init_node(_sparseTree_t *node) {
    _nodeHash_t *nd;
    //printf("init called for n, d, o = %d, %d, %d\n", node->n, node->depth, node->ordinal);
    assert(node->nodeData == NULL);
    assert(node->clear == NULL);
    node->nodeData = (void *)malloc(sizeof(_nodeHash_t));
    node->clear = _clear_node;
    nd = (_nodeHash_t *)node->nodeData;
    nd->hd = _hashfunc(node->depth);
    nd->ho = _hashfunc(node->ordinal);
    allocated_nodes++;
}

START_TEST(test_sparsetree_walk)
    int i, j, anodes;
    uint64_t k, levelsz;
    sparseTree_t tree;
    sparseTree_ptr nptr;
    _nodeHash_t *nd;
    
    assert(allocated_nodes == 0);

    for (i = 2; i < 9; i++) {
        printf("------------\nTree Size = %d\n------------\n", i);
        sparseTree_init(tree, i, _init_node);
        anodes = 0;
        assert(allocated_nodes == 1);
        for (j = 0; j < 8; j++) {
            levelsz = 1;
            for (k = 0; k < j; k++) {
                levelsz *= i;
            }
            printf("walking tree level %d, %ld nodes in level\n", j, levelsz);
            for (k = 0; k < levelsz; k++) {
                //printf("finding node @(%d, %d)\n", j, k);
                nptr = sparseTree_find_by_address(tree, j, k);
                assert(nptr->depth == j);
                assert(nptr->ordinal == k);
                nd = (_nodeHash_t *)nptr->nodeData;
                assert(nd->hd == _hashfunc(j));
                assert(nd->ho == _hashfunc(k));
                //printf("node validated @(%d, %d), hash(%02X, %02X)\n", j, k, nd->hd, nd->ho);
            }
            anodes += levelsz;
            assert (allocated_nodes == anodes);
        }
        sparseTree_clear(tree);
        assert(allocated_nodes == 0);
    }
END_TEST

START_TEST(test_sparsetree_random)
    int i, j;
    uint64_t k, levelsz;
    sparseTree_t tree;
    sparseTree_ptr nptr;
    _nodeHash_t *nd;
    
    assert(allocated_nodes == 0);

    for (i = 2; i < 65; i *= 2) {
        printf("------------\nTree Size = %d\n------------\n", i);
        sparseTree_init(tree, i, _init_node);
        assert(allocated_nodes == 1);
        for (j = 0; j < 9; j++) {
            levelsz = 1;
            for (k = 0; k < j; k++) {
                levelsz *= i;
            }
            printf("finding random node @ tree level %d, %ld nodes in level\n", j, levelsz);
            // note: rand is probably not as big as uint64_t... but still random
            k = ((uint64_t)rand()) * ((uint64_t)rand()) % levelsz ;
            printf("finding node @(%d, %ld)\n", j, k);
            nptr = sparseTree_find_by_address(tree, j, k);
            assert(nptr->depth == j);
            assert(nptr->ordinal == k);
            nd = (_nodeHash_t *)nptr->nodeData;
            assert(nd->hd == _hashfunc(j));
            assert(nd->ho == _hashfunc(k));
            printf("node validated @(%d, %ld), hash(%02X, %02X)\n", j, k, nd->hd, nd->ho);
        }
        sparseTree_clear(tree);
        assert(allocated_nodes == 0);
    }
END_TEST

static Suite *sparseTree_test_suite(void) {
    Suite *s;
    TCase *tc;
    
    s = suite_create("Sparse Tree implementation");
    tc = tcase_create("allocation and traversal");

    // set 10 second timeout instead of default 4
    tcase_set_timeout(tc, 10.0);

    tcase_add_test(tc, test_sparsetree_walk);
    tcase_add_test(tc, test_sparsetree_random);
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

#ifdef SAFE_CLEAN
    _enable_gmp_safe_clean();
#endif

    s = sparseTree_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
