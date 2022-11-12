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
#include "smithy/stdlib/buffer.h"

#include <bearssl.h>

/// A trust store serves as the base for all certificate chains. If a chain is
/// not anchored in a trust store, then the chain is not trusted even if it has
/// been constructed correctly.
///
/// This struct shall be treated as opaque.
typedef struct {
  br_x509_trust_anchor *anchors;
  size_t num_anchors;
} sm_trust_store;

/// Lifetime management for a trust store.
void sm_trust_store_init(sm_trust_store *t);
void sm_trust_store_cleanup(sm_trust_store *t);

/// Needed for SM_AUTO macro
static inline void free_sm_trust_store(sm_trust_store *t) {
  sm_trust_store_cleanup(t);
}

void sm_add_trust_anchor(sm_trust_store *t, const sm_buffer ta);
