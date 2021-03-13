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

#pragma once

#include "smithy/stdlib/ptr_int_pair.h"
#include "smithy/stdlib/typed_vector.h"
#include <stddef.h>

// If the stored boolean is true, the current node is owned. This means that
// the types stored with an sm_ilist must be at least 2 byte aligned.

// The simplest way to use this object is to take advantage of the C feature
// that you can cast a struct pointer to a pointer to its first member. That
// means that given:
//    typedef struct {
//       sm_itree tree;
//       void *data;
//    } foo;
//    foo f;
// You should be able to use
//    sm_tree_<>(&f)

typedef struct sm_itree_ {
  struct sm_itree_ *parent;
  sm_buffer children;
} sm_itree;

#define sm_empty_itree                                                         \
  (sm_itree) { .parent = NULL, .children = sm_empty_buffer }

void sm_itree_init(sm_itree *root);
void sm_itree_free(sm_itree *root, void free_cb(void *));
bool sm_itree_add_child(sm_itree *parent, sm_itree *child);
bool sm_itree_take_child(sm_itree *parent, sm_itree *child);

// Algorithms on the tree start here
sm_itree *sm_itree_get_root(sm_itree *node);

typedef enum {
  SM_POSTORDER,
  SM_REVERSE_POSTORDER,
  SM_PREORDER,
  SM_REVERSE_PREORDER,
  SM_INORDER,
  SM_REVERSE_INORDER,
} sm_itree_traversal;

// The foreach function takes a user-provided context and the node. Return true
// to continue, false to stop iteration.
typedef bool (*sm_itree_foreach_fn)(void *, sm_itree *);
// This function can take any node as the root of the traversal. It only
// traverses the subtree of that node.
void sm_itree_traverse(sm_itree *node, sm_itree_traversal traversal,
                       sm_itree_foreach_fn f, void *ctx);
