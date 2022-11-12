//
// Copyright 2022 Aman LaChapelle
// Full license at keyderiver/LICENSE.txt
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

#include "smithy/crypto/cert_chain.h"
#include "smithy/crypto/sign_algorithm.h"
#include "smithy/stdlib/buffer.h"

#include <bearssl.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// Provides a vtable for the verification engine. Because much of the
/// functionality is duplicated between the various algorithms, the vtable
/// allows us to abstract over those details.
typedef struct sm_verify_engine_ sm_verify_engine;
struct sm_verify_engine_ {
  size_t context_size;
  bool (*verify)(const sm_verify_engine **ctx, const sm_buffer in,
                 const sm_buffer sig, const sm_certificate_chain *chain);
  void (*cleanup)(const sm_verify_engine **ctx);
};

extern const sm_verify_engine sm_rs256_verify_vtable;
extern const sm_verify_engine sm_es256_verify_vtable;

typedef struct {
  const sm_verify_engine *vtable;
} sm_rsa_verify_ctx_;

typedef sm_rsa_verify_ctx_ sm_rs256_verify_ctx;

typedef struct {
  const sm_verify_engine *vtable;
} sm_ec_verify_ctx_;

typedef sm_ec_verify_ctx_ sm_es256_verify_ctx;

typedef union {
  const sm_verify_engine *vtable;
  sm_rsa_verify_ctx_ rsa;
  sm_ec_verify_ctx_ ec;
} sm_verify_ctx;

/// Initializers for verification contexts. These must be specific to the
/// signing algorithm because this initializes the vtable.
void sm_rs256_verify_init(sm_verify_ctx *ctx);
void sm_es256_verify_init(sm_verify_ctx *ctx);

/// Get the algorithm used by the signing engine.
sm_sign_algorithm sm_verify_engine_get_alg(const sm_verify_ctx *ctx);
/// Given a buffer and a signature, verify the signature based on the input
/// buffer and the provided certificate chain. Returns true if the signature is
/// correct, false if not.
bool sm_verify_engine_verify(const sm_verify_ctx *ctx, const sm_buffer in,
                             const sm_buffer sig,
                             const sm_certificate_chain *chain);
/// Clean up the verify engine context.
void sm_verify_engine_cleanup(const sm_verify_ctx *ctx);

/// Needed for SM_AUTO macro
static inline void free_sm_verify_ctx(sm_verify_ctx *c) {
  sm_verify_engine_cleanup(c);
}
