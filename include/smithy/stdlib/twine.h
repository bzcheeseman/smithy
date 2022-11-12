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

#include "smithy/stdlib/buffer.h"
#include "smithy/stdlib/linked_list.h"

/// Similar in feeling to llvm::Twine c.f.
/// https://llvm.org/doxygen/Twine_8h_source.html but different in that this is
/// a linked-list rather than a binary tree. Most twines built from this ended
/// up being basically linked lists in a binary tree data structure, so I
/// decided to just use a linked list instead.

typedef struct {
  sm_ilist list_;
  sm_buffer data;
} sm_twine;

static inline void free_sm_twine(const sm_twine *t) {
  if (t) {
    free_sm_buffer(&t->data);
  }
}

/// Check if the twine is empty.
static inline bool sm_twine_is_empty(const sm_twine t) {
  return sm_ilist_next((sm_ilist *)&t) == NULL && sm_buffer_empty(t.data);
}

#define sm_twine_alias_str(str)                                                \
  (sm_twine) { .list_ = sm_empty_ilist, .data = sm_buffer_alias_str((str)) }

#define sm_twine_alias_buffer(buf)                                             \
  (sm_twine) { .list_ = sm_empty_ilist, .data = (buf) }

/// Append a twine to another twine. NOTE: be careful, this is the same
/// complexity as sm_ilist_push_back. Try to use this on a pointer to the last
/// twine element. The function returns the last twine element, properly
/// emplaced.
sm_twine *sm_twine_append(sm_twine *t, sm_twine *elt);

/// Concat the elements of the twine into `dest`.
void sm_twine_render(const sm_twine t, sm_buffer *dest);
