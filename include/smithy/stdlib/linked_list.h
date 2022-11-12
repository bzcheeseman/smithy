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

#include "smithy/stdlib/alloc.h"
#include "smithy/stdlib/ptr_int_pair.h"

#include <stddef.h>

// The simplest way to use this object is to take advantage of the C feature
// that you can cast a struct pointer to a pointer to its first member. That
// means that given:
//    typedef struct {
//       sm_ilist list;
//       void *data;
//    } foo;
//    foo f;
// You should be able to use
//    sm_list_<>(&f)

/// Provides an intrusive pointer singly-linked list with a notion of ownership.
typedef struct sm_ilist_ {
  // If the stored boolean is true, the current node is owned. This means that
  // the types stored with an sm_ilist must be at least 2 byte aligned. This is
  // guaranteed because the alignment of this struct is 8 bytes, and therefore
  // any struct that embeds this one must be at least 8 bytes.
  sm_ptr_u1_pair next;
} sm_ilist;

#define sm_empty_ilist                                                         \
  (sm_ilist) { .next = sm_ptr_u1_pair_false(NULL) }

#define sm_ilist_for_each(begin, iter)                                         \
  _Pragma("clang diagnostic push")                                             \
      _Pragma("clang diagnostic ignored \"-Wlanguage-extension-token\"") for ( \
          ((iter)) = (begin); ((iter)) != NULL;                                \
          ((iter)) = (typeof(iter))sm_ptr_u1_pair_get_ptr(                     \
              ((sm_ilist *)(iter))->next)) _Pragma("clang diagnostic pop")

/// Iterate the whole list and just clean it up
void sm_ilist_free(sm_ilist *l, void free_cb(void *));

/// Get the next sm_ilist pointer.
static inline sm_ilist *sm_ilist_next(sm_ilist *l) {
  return sm_ptr_u1_pair_get_ptr(l->next);
}

/// Have the list take ownership of the current sm_ilist node.
static inline sm_ilist *sm_ilist_take(sm_ilist *l) {
  // Just set the ownership bit
  sm_ptr_u1_pair_set_int(&l->next, 1);
  return l;
}

/// NOTE: push_* API does not take ownership of list item, while take_* API
/// does. If the list has ownership of the element, it can be freed with
/// sm_ilist_free.

/// Push an item onto the front of the linked list. O(1) and assumes l is the
/// head of the list.
void sm_ilist_push_front(sm_ilist *l, sm_ilist *elt);
void sm_ilist_take_front(sm_ilist *l, sm_ilist *elt);

/// NOTE: This takes O(end - l) where end is the last element in the list
void sm_ilist_push_back(sm_ilist *l, sm_ilist *elt);
void sm_ilist_take_back(sm_ilist *l, sm_ilist *elt);

/// To get the element at the front of the list, just take the front ptr
/// Get the element at the back of the list
void sm_ilist_back(sm_ilist *l, sm_ilist **elt);

/// Get the length of the list. This is O(N), be careful.
size_t sm_ilist_length(const sm_ilist *l);
