//
// Copyright 2022 Aman LaChapelle
// Full license at smithy/LICENSE.txt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/tree.h"
#include <printf.h>

typedef struct {
  sm_itree tree;
  size_t data;
} foo;

typedef struct {
  size_t i;
  size_t data[6];
} simple_traversal_ctx;

bool simple_traverse(void *c, sm_itree *node) {
  simple_traversal_ctx *ctx = c;
  foo *f = (foo *)node;
  ctx->data[ctx->i++] = f->data;
  return true;
}

// Build the tree:
//       0
//      /|\
//     1 2 3
//      / \
//     4   5
// So the postorder traversal is:
// 1, 4, 5, 2, 3, 0
// And the reverse is:
// 3, 5, 4, 2, 1, 0
// The preorder traversal is:
// 0, 1, 2, 4, 5, 3
// And the reverse is:
// 0, 3, 2, 5, 4, 1
// The inorder traversal is:
// 1, 4, 2, 5, 0, 3
// And the reverse is:
// 3, 5, 2, 4, 0, 1

static foo simple_tree[6] = {{sm_empty_itree, 0}, {sm_empty_itree, 1},
                             {sm_empty_itree, 2}, {sm_empty_itree, 3},
                             {sm_empty_itree, 4}, {sm_empty_itree, 5}};
void build_simple_tree(void) {
  sm_itree_add_child((sm_itree *)&simple_tree[0], (sm_itree *)&simple_tree[1]);
  sm_itree_add_child((sm_itree *)&simple_tree[0], (sm_itree *)&simple_tree[2]);
  sm_itree_add_child((sm_itree *)&simple_tree[0], (sm_itree *)&simple_tree[3]);
  sm_itree_add_child((sm_itree *)&simple_tree[2], (sm_itree *)&simple_tree[4]);
  sm_itree_add_child((sm_itree *)&simple_tree[2], (sm_itree *)&simple_tree[5]);
}

void simple_postorder(void) {
  simple_traversal_ctx ctx = {.i = 0,
                              .data = {
                                  0,
                              }};
  sm_itree_traverse((sm_itree *)&simple_tree[0], SM_POSTORDER, &simple_traverse,
                    &ctx);
  SM_ASSERT(ctx.data[0] == 1);
  SM_ASSERT(ctx.data[1] == 4);
  SM_ASSERT(ctx.data[2] == 5);
  SM_ASSERT(ctx.data[3] == 2);
  SM_ASSERT(ctx.data[4] == 3);
  SM_ASSERT(ctx.data[5] == 0);
}

void simple_reverse_postorder(void) {
  simple_traversal_ctx ctx = {.i = 0,
                              .data = {
                                  0,
                              }};
  sm_itree_traverse((sm_itree *)&simple_tree[0], SM_REVERSE_POSTORDER,
                    &simple_traverse, &ctx);
  SM_ASSERT(ctx.data[0] == 3);
  SM_ASSERT(ctx.data[1] == 5);
  SM_ASSERT(ctx.data[2] == 4);
  SM_ASSERT(ctx.data[3] == 2);
  SM_ASSERT(ctx.data[4] == 1);
  SM_ASSERT(ctx.data[5] == 0);
}

void simple_preorder(void) {
  simple_traversal_ctx ctx = {.i = 0,
                              .data = {
                                  0,
                              }};
  sm_itree_traverse((sm_itree *)&simple_tree[0], SM_PREORDER, &simple_traverse,
                    &ctx);
  SM_ASSERT(ctx.data[0] == 0);
  SM_ASSERT(ctx.data[1] == 1);
  SM_ASSERT(ctx.data[2] == 2);
  SM_ASSERT(ctx.data[3] == 4);
  SM_ASSERT(ctx.data[4] == 5);
  SM_ASSERT(ctx.data[5] == 3);
}

void simple_reverse_preorder(void) {
  simple_traversal_ctx ctx = {.i = 0,
                              .data = {
                                  0,
                              }};
  sm_itree_traverse((sm_itree *)&simple_tree[0], SM_REVERSE_PREORDER,
                    &simple_traverse, &ctx);
  SM_ASSERT(ctx.data[0] == 0);
  SM_ASSERT(ctx.data[1] == 3);
  SM_ASSERT(ctx.data[2] == 2);
  SM_ASSERT(ctx.data[3] == 5);
  SM_ASSERT(ctx.data[4] == 4);
  SM_ASSERT(ctx.data[5] == 1);
}

void simple_inorder(void) {
  simple_traversal_ctx ctx = {.i = 0,
                              .data = {
                                  0,
                              }};
  sm_itree_traverse((sm_itree *)&simple_tree[0], SM_INORDER, &simple_traverse,
                    &ctx);
  SM_ASSERT(ctx.data[0] == 1);
  SM_ASSERT(ctx.data[1] == 4);
  SM_ASSERT(ctx.data[2] == 2);
  SM_ASSERT(ctx.data[3] == 5);
  SM_ASSERT(ctx.data[4] == 0);
  SM_ASSERT(ctx.data[5] == 3);
}

void simple_reverse_inorder(void) {
  simple_traversal_ctx ctx = {.i = 0,
                              .data = {
                                  0,
                              }};
  sm_itree_traverse((sm_itree *)&simple_tree[0], SM_REVERSE_INORDER,
                    &simple_traverse, &ctx);
  SM_ASSERT(ctx.data[0] == 3);
  SM_ASSERT(ctx.data[1] == 5);
  SM_ASSERT(ctx.data[2] == 2);
  SM_ASSERT(ctx.data[3] == 4);
  SM_ASSERT(ctx.data[4] == 0);
  SM_ASSERT(ctx.data[5] == 1);
}

int main(void) {
  build_simple_tree();
  simple_postorder();
  simple_reverse_postorder();
  simple_preorder();
  simple_reverse_preorder();
  simple_inorder();
  simple_reverse_inorder();
  sm_itree_cleanup((sm_itree *)&simple_tree[0], NULL);
}
