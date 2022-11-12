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

#include "smithy/stdlib/tree.h"

#include "smithy/stdlib/alloc.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/queue.h"

void sm_itree_init(sm_itree *root) { *root = sm_empty_itree; }

#define childlist_gep(list, idx) sm_typed_vector_gep(sm_ptr_u1_pair, list, idx)
#define childlist_at(list, idx) sm_typed_vector_at(sm_ptr_u1_pair, list, idx)
#define childlist_len(list) sm_typed_vector_length(sm_ptr_u1_pair, list)

// TODO: to use this as a search, we have to be able to return that something
//       was found.
typedef bool (*traverse_fn)(void *ctx, sm_ptr_u1_pair node);

static void itree_bfs_impl(sm_ptr_u1_pair root, traverse_fn fn, void *ctx) {
  SM_AUTO(sm_growable_queue) bfs_growable_queue;
  sm_growable_queue_init(&bfs_growable_queue, sizeof(sm_ptr_u1_pair));

  const sm_queue **bfs_q = (const sm_queue **)&bfs_growable_queue;

  (*bfs_q)->force_push(bfs_q, &root);

  while (!(*bfs_q)->empty(bfs_q)) {
    sm_ptr_u1_pair next;
    SM_ASSERT((*bfs_q)->pop(bfs_q, (void *)&next));
    sm_itree *tree_node = sm_ptr_u1_pair_get_ptr(next);

    // Push all the children onto the queue.
    for (size_t child = 0; child < childlist_len(tree_node->children);
         ++child) {
      (*bfs_q)->force_push(bfs_q, childlist_gep(tree_node->children, child));
    }

    if (!fn(ctx, next)) {
      return;
    }
  }
}

static void itree_dfs_impl(sm_ptr_u1_pair root, traverse_fn fn, void *ctx) {
  // TODO: make this iterative with a stack.
  if (!fn(ctx, root)) {
    return;
  }
  sm_itree *tree_node = sm_ptr_u1_pair_get_ptr(root);
  for (size_t child = 0; child < childlist_len(tree_node->children); ++child) {
    itree_dfs_impl(childlist_at(tree_node->children, child), fn, ctx);
  }
}

typedef struct {
  sm_ilist list;
  sm_ptr_u1_pair node;
} traversal_stack_node;

void traversal_stack_push(traversal_stack_node **head, sm_ptr_u1_pair ptr) {
  traversal_stack_node *node = sm_malloc(sizeof(traversal_stack_node));
  node->node = ptr;
  if (*head != NULL) {
    // Take ownership of the node.
    sm_ilist_take_front(*head, node);
  }
  // `head` is the new node.
  *head = node;
}

sm_ptr_u1_pair traversal_stack_pop(traversal_stack_node **head) {
  if (*head == NULL) {
    return sm_ptr_u1_pair_false(NULL);
  }

  sm_ptr_u1_pair out = (*head)->node;
  traversal_stack_node *next =
      (traversal_stack_node *)sm_ilist_next((sm_ilist *)*head);
  sm_free(*head);
  *head = next;
  return out;
}

sm_ptr_u1_pair traversal_stack_peek(traversal_stack_node *head) {
  if (head == NULL) {
    return sm_ptr_u1_pair_false(NULL);
  }

  return head->node;
}

bool traversal_stack_empty(const traversal_stack_node *head) {
  return head == NULL;
}

static void itree_preorder_traverse_impl(sm_ptr_u1_pair root, bool reverse,
                                         traverse_fn fn, void *ctx) {

  traversal_stack_node *traverse_stack = NULL;
  traversal_stack_push(&traverse_stack, root);
  while (!traversal_stack_empty(traverse_stack)) {
    sm_ptr_u1_pair top = traversal_stack_pop(&traverse_stack);
    if (fn && !fn(ctx, top)) {
      return;
    }

    sm_itree *tree_node = sm_ptr_u1_pair_get_ptr(top);
    if (reverse) {
      // Push the nodes in order for reverse-pre-order traversal (LIFO).
      for (size_t i = 0; i < childlist_len(tree_node->children); ++i) {
        traversal_stack_push(&traverse_stack,
                             childlist_at(tree_node->children, i));
      }
    } else {
      // Push the nodes in reverse order for pre-order traversal (LIFO).
      // Unsigned wrapping arithmetic is well-defined in C - `i` will become
      // greater than `ub + 1` when it wraps.
      size_t ub = childlist_len(tree_node->children) - 1;
      for (size_t i = ub; i < ub + 1; --i) {
        traversal_stack_push(&traverse_stack,
                             childlist_at(tree_node->children, i));
      }
    }
  }
  SM_ASSERT(traversal_stack_empty(traverse_stack));
}

static void itree_postorder_traverse_impl(sm_ptr_u1_pair root, bool reverse,
                                          traverse_fn fn, void *ctx) {
  traversal_stack_node *traverse_stack = NULL;
  traversal_stack_push(&traverse_stack, root);
  sm_ptr_u1_pair last_visited = {
      0,
  };
  while (!traversal_stack_empty(traverse_stack)) {
    sm_ptr_u1_pair peek = traversal_stack_peek(traverse_stack);
    sm_itree *tree_node = sm_ptr_u1_pair_get_ptr(peek);

    // If we've visited all the children of this node, or it has
    // no children, then pop this node and visit it.
    size_t last_child_idx =
        reverse ? 0 : childlist_len(tree_node->children) - 1;
    if (childlist_len(tree_node->children) == 0 ||
        sm_ptr_u1_pair_get_ptr(
            childlist_at(tree_node->children, last_child_idx)) ==
            sm_ptr_u1_pair_get_ptr(last_visited)) {
      sm_ptr_u1_pair top = traversal_stack_pop(&traverse_stack);
      SM_ASSERT(top.value == peek.value);
      last_visited = top;
      if (fn && !fn(ctx, top)) {
        return;
      }
      continue;
    }

    if (reverse) {
      // Otherwise, push the children from left to right onto the stack (LIFO).
      for (size_t i = 0; i < childlist_len(tree_node->children); ++i) {
        traversal_stack_push(&traverse_stack,
                             childlist_at(tree_node->children, i));
      }
    } else {
      // Otherwise, push the children from right to left onto the stack (LIFO).
      // Unsigned wrapping arithmetic is well-defined in C - `i` will become
      // greater than `ub + 1` when it wraps.
      size_t ub = childlist_len(tree_node->children) - 1;
      for (size_t i = ub; i < ub + 1; --i) {
        traversal_stack_push(&traverse_stack,
                             childlist_at(tree_node->children, i));
      }
    }
  }
  SM_ASSERT(traversal_stack_empty(traverse_stack));
}

static void itree_inorder_traverse_impl(sm_ptr_u1_pair root, bool reverse,
                                        traverse_fn fn, void *ctx) {
  traversal_stack_node *traverse_stack = NULL;
  traversal_stack_push(&traverse_stack, root);
  while (!traversal_stack_empty(traverse_stack)) {
    sm_ptr_u1_pair top = traversal_stack_pop(&traverse_stack);
    sm_itree *tree_node = sm_ptr_u1_pair_get_ptr(top);
    // If top is not NULL, then process it.
    if (tree_node != NULL) {
      // No children, so push myself, and then NULL into top.
      if (childlist_len(tree_node->children) == 0) {
        traversal_stack_push(&traverse_stack, top);
        traversal_stack_push(&traverse_stack, sm_ptr_u1_pair_false(NULL));
        continue;
      }

      if (reverse) {
        // Push the first child onto the stack to process last. No NULL because
        // we don't know if it has children.
        traversal_stack_push(&traverse_stack,
                             childlist_at(tree_node->children, 0));

        // Then push the parent onto the stack (top in this case) and a NULL so
        // it gets handled.
        traversal_stack_push(&traverse_stack, top);
        traversal_stack_push(&traverse_stack, sm_ptr_u1_pair_false(NULL));
        // Push the children onto the stack, left-to-right, second to last. No
        // NULL because the child may have children.
        for (size_t i = 1; i < childlist_len(tree_node->children); ++i) {
          traversal_stack_push(&traverse_stack,
                               childlist_at(tree_node->children, i));
        }
      } else {
        // Push the last child onto the stack to process last. No NULL because
        // we don't know if it has children.
        traversal_stack_push(
            &traverse_stack,
            childlist_at(tree_node->children,
                         childlist_len(tree_node->children) - 1));

        // Then push the parent onto the stack (top in this case) and a NULL so
        // it gets handled.
        traversal_stack_push(&traverse_stack, top);
        traversal_stack_push(&traverse_stack, sm_ptr_u1_pair_false(NULL));
        // Push the children onto the stack, right to left, second-to-last to
        // first. No NULL because the child may have children. Unsigned wrapping
        // arithmetic is well-defined in C - `i` will become greater than `ub +
        // 1` when it wraps.
        size_t ub = childlist_len(tree_node->children) - 2;
        for (size_t i = ub; i < ub + 1; --i) {
          traversal_stack_push(&traverse_stack,
                               childlist_at(tree_node->children, i));
        }
      }

      continue;
    }

    // Otherwise, pop off the stack and visit the node.
    top = traversal_stack_pop(&traverse_stack);
    if (fn && !fn(ctx, top)) {
      return;
    }
  }
  SM_ASSERT(traversal_stack_empty(traverse_stack));
}

typedef struct {
  void (*free_cb)(void *);
} free_fn_ctx;

static bool itree_free_foreach_fn(void *ctx, sm_ptr_u1_pair node) {
  free_fn_ctx *c = ctx;
  // Free the children, then only if it's owned should we free the node itself.
  sm_itree *n = sm_ptr_u1_pair_get_ptr(node);
  sm_buffer_cleanup(n->children);
  // If the node is owned, then free it.
  if (sm_ptr_u1_pair_get_int(node) == 1) {
    if (c->free_cb) {
      c->free_cb((void *)n);
    }
    sm_free(n);
  }
  return true;
}

void sm_itree_cleanup(sm_itree *root, void free_cb(void *)) {
  if (root == NULL) {
    return;
  }

  free_fn_ctx ctx;
  ctx.free_cb = free_cb;
  itree_postorder_traverse_impl(sm_ptr_u1_pair_false(root), false,
                                &itree_free_foreach_fn, &ctx);
}

bool sm_itree_add_child(sm_itree *parent, sm_itree *child) {
  sm_ptr_u1_pair child_pair = sm_ptr_u1_pair_false(child);
  sm_typed_vector_push(&parent->children, child_pair);
  child->parent = parent;
  return true;
}

bool sm_itree_take_child(sm_itree *parent, sm_itree *child) {
  sm_ptr_u1_pair child_pair = sm_ptr_u1_pair_true(child);
  sm_typed_vector_push(&parent->children, child_pair);
  child->parent = parent;
  return true;
}

sm_itree *sm_itree_get_root(sm_itree *node) {
  sm_itree *p = node->parent;
  while (p->parent) {
    p = p->parent;
  }
  return p;
}

typedef struct {
  void *ctx;
  sm_itree_foreach_fn f;
} foreach_wrapper_ctx;

static bool foreach_wrapper(void *ctx, sm_ptr_u1_pair node) {
  foreach_wrapper_ctx *c = ctx;
  return c->f(c->ctx, sm_ptr_u1_pair_get_ptr(node));
}

void sm_itree_traverse(sm_itree *node, sm_itree_traversal traversal,
                       sm_itree_foreach_fn f, void *ctx) {
  if (node == NULL) {
    return;
  }

  foreach_wrapper_ctx c = {.ctx = ctx, .f = f};
  switch (traversal) {
  case SM_POSTORDER:
    itree_postorder_traverse_impl(sm_ptr_u1_pair_false(node), false,
                                  foreach_wrapper, &c);
    break;
  case SM_REVERSE_POSTORDER:
    itree_postorder_traverse_impl(sm_ptr_u1_pair_false(node), true,
                                  foreach_wrapper, &c);
    break;
  case SM_PREORDER:
    itree_preorder_traverse_impl(sm_ptr_u1_pair_false(node), false,
                                 foreach_wrapper, &c);
    break;
  case SM_REVERSE_PREORDER:
    itree_preorder_traverse_impl(sm_ptr_u1_pair_false(node), true,
                                 foreach_wrapper, &c);
    break;
  case SM_INORDER:
    itree_inorder_traverse_impl(sm_ptr_u1_pair_false(node), false,
                                foreach_wrapper, &c);
    break;
  case SM_REVERSE_INORDER:
    itree_inorder_traverse_impl(sm_ptr_u1_pair_false(node), true,
                                foreach_wrapper, &c);
    break;
  }
}
