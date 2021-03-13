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

#include "smithy/stdlib/linked_list.h"

void sm_ilist_free(sm_ilist *l, void (*free_cb)(void *)) {
  // Termination condition
  if (l == NULL) {
    return;
  }

  // Copy this iterator
  sm_ilist iter = *l;
  // The integer part indicates that that node owns its memory
  if (sm_ptr_u1_pair_get_int(l->next) == 1) {
    if (free_cb) {
      free_cb((void *)l);
    }
    sm_free(l);
  }

  sm_ilist_free(sm_ptr_u1_pair_get_ptr(iter.next), free_cb);
}

void sm_ilist_push_front(sm_ilist *l, sm_ilist *elt) {
  sm_ptr_u1_pair_set_ptr(&elt->next, l);
  sm_ptr_u1_pair_set_int(&elt->next, 0);
}

void sm_ilist_take_front(sm_ilist *l, sm_ilist *elt) {
  sm_ptr_u1_pair_set_ptr(&elt->next, l);
  // If the boolean in elt's next ptr is 1, the list owns elt
  sm_ptr_u1_pair_set_int(&elt->next, 1);
}

// TODO: what kinds of tricks can we play to make push_back and length faster?

void sm_ilist_push_back(sm_ilist *l, sm_ilist *elt) {
  sm_ilist *iter = l;
  while (sm_ptr_u1_pair_get_ptr(iter->next) != NULL) {
    iter = sm_ptr_u1_pair_get_ptr(iter->next);
  }
  // Iter points at the end, so add elt there.
  sm_ptr_u1_pair_set_ptr(&iter->next, elt);
  sm_ptr_u1_pair_set_int(&iter->next, 0);
  sm_ptr_u1_pair_set_ptr(&elt->next, NULL);
}

void sm_ilist_take_back(sm_ilist *l, sm_ilist *elt) {
  sm_ilist *iter = l;
  while (sm_ptr_u1_pair_get_ptr(iter->next) != NULL) {
    iter = sm_ptr_u1_pair_get_ptr(iter->next);
  }
  // Iter points at the end, so add elt there.
  sm_ptr_u1_pair_set_ptr(&iter->next, elt);
  // If the boolean in elt's next ptr is 1, the list owns elt
  sm_ptr_u1_pair_set_int(&elt->next, 1);
  sm_ptr_u1_pair_set_ptr(&elt->next, NULL);
}

void sm_ilist_back(sm_ilist *l, sm_ilist **elt) {
  *elt = l;
  // Walk the list until elt points at the element without a next (which is the
  // end)
  while (sm_ptr_u1_pair_get_ptr((*elt)->next) != NULL) {
    (*elt) = sm_ptr_u1_pair_get_ptr((*elt)->next);
  }
}

size_t sm_ilist_length(const sm_ilist *l) {
  if (!l) {
    return 0;
  }

  size_t out = 0;
  const sm_ilist *iter;
  sm_ilist_for_each(l, iter) { ++out; }
  return out;
}
