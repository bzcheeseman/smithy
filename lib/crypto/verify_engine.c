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

#include "smithy/crypto/verify_engine.h"
#include "smithy/stdlib/b64.h"

sm_sign_algorithm sm_verify_engine_get_alg(const sm_verify_ctx *ctx) {
  if (ctx->vtable == &sm_rs256_verify_vtable) {
    return RS256;
  } else if (ctx->vtable == &sm_es256_verify_vtable) {
    return ES256;
  }

  return UNKNOWN;
}

bool sm_verify_engine_verify(const sm_verify_ctx *ctx, const sm_buffer in,
                             const sm_buffer sig,
                             const sm_certificate_chain *chain) {
  return ctx->vtable->verify((const sm_verify_engine **)&ctx->vtable, in, sig,
                             chain);
}

void sm_verify_engine_cleanup(const sm_verify_ctx *ctx) {
  ctx->vtable->cleanup((const sm_verify_engine **)&ctx->vtable);
}
