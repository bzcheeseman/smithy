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

#include "smithy/crypto/sign_engine.h"

sm_sign_algorithm sm_sign_engine_get_alg(const sm_sign_ctx *ctx) {
  if (ctx->vtable == &sm_rs256_sign_vtable) {
    return RS256;
  } else if (ctx->vtable == &sm_es256_sign_vtable) {
    return ES256;
  }

  return UNKNOWN;
}

void sm_sign_engine_load_privkey(const sm_sign_ctx *ctx, const sm_buffer key) {
  ctx->vtable->load_privkey((const sm_sign_engine **)&ctx->vtable, key);
}

bool sm_sign_engine_sign(const sm_sign_ctx *ctx, const sm_buffer in,
                         sm_buffer *sig) {
  return ctx->vtable->sign((const sm_sign_engine **)&ctx->vtable, in, sig);
}

void sm_sign_engine_cleanup(const sm_sign_ctx *ctx) {
  ctx->vtable->cleanup((const sm_sign_engine **)&ctx->vtable);
}
