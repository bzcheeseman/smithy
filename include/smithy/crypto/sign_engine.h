//
// Copyright 2022 Aman LaChapelle
// Full license at auth/LICENSE.txt
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

#include "smithy/crypto/sign_algorithm.h"
#include "smithy/stdlib/buffer.h"

#include <bearssl.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// Provides a vtable for the signing engine. Because much of the functionality
/// is duplicated between the various algorithms, the vtable allows us to
/// abstract over those details.
typedef struct sm_sign_engine_ sm_sign_engine;
struct sm_sign_engine_ {
  size_t context_size;
  void (*load_privkey)(const sm_sign_engine **ctx, const sm_buffer key);
  bool (*sign)(const sm_sign_engine **ctx, const sm_buffer in, sm_buffer *sig);
  void (*cleanup)(const sm_sign_engine **ctx);
};

extern const sm_sign_engine sm_rs256_sign_vtable;
extern const sm_sign_engine sm_es256_sign_vtable;

typedef struct {
  const sm_sign_engine *vtable;
  br_rsa_private_key key;
} sm_rsa_sign_ctx_;

typedef sm_rsa_sign_ctx_ sm_rs256_sign_ctx;

typedef struct {
  const sm_sign_engine *vtable;
  br_ec_private_key key;
} sm_ec_sign_ctx_;

typedef sm_ec_sign_ctx_ sm_es256_sign_ctx;

typedef union {
  const sm_sign_engine *vtable;
  sm_rsa_sign_ctx_ rsa;
  sm_ec_sign_ctx_ ec;
} sm_sign_ctx;

/// Initializers for signing contexts. These must be specific to the signing
/// algorithm because this initializes the vtable.
void sm_rs256_sign_init(sm_sign_ctx *ctx);
void sm_es256_sign_init(sm_sign_ctx *ctx);

/// Get the algorithm used by the signing engine.
sm_sign_algorithm sm_sign_engine_get_alg(const sm_sign_ctx *ctx);
/// Load the given private key into the sign context.
void sm_sign_engine_load_privkey(const sm_sign_ctx *ctx, const sm_buffer key);
/// Sign `in` and place the signature into `sig`.
bool sm_sign_engine_sign(const sm_sign_ctx *ctx, const sm_buffer in,
                         sm_buffer *sig);
/// Clean up the sign engine. This frees any internal state.
void sm_sign_engine_cleanup(const sm_sign_ctx *ctx);

/// Needed for SM_AUTO macro
static inline void free_sm_sign_ctx(sm_sign_ctx *c) {
  sm_sign_engine_cleanup(c);
}
