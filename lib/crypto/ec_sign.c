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

#include "privkey_helpers.h"

#include "smithy/crypto/sign_engine.h"
#include "smithy/stdlib/assert.h"

#include <bearssl.h>

void sm_es256_sign_init(sm_sign_ctx *ctx) {
  ctx->vtable = &sm_es256_sign_vtable;
}

static void sm_ec_load_privkey(sm_ec_sign_ctx_ *c, const sm_buffer key) {
  br_skey_decoder_context decoder_ctx;
  br_skey_decoder_init(&decoder_ctx);

  sm_load_privkey(key, &decoder_ctx);

  // Set up the engine's signing pkey
  int keyty = br_skey_decoder_key_type(&decoder_ctx);
  SM_ASSERT(keyty == BR_KEYTYPE_EC &&
            "Cannot use non-EC pkey for EC signing context");
  // We have to do a deep copy, which requires introspection
  const br_ec_private_key *pkey = br_skey_decoder_get_ec(&decoder_ctx);
  c->key.curve = pkey->curve;
  c->key.x = sm_calloc(pkey->xlen, 1);
  c->key.xlen = pkey->xlen;
  memcpy(c->key.x, pkey->x, pkey->xlen);
}

static bool sm_es256_sign(sm_es256_sign_ctx *c, const sm_buffer in,
                          sm_buffer *sig) {
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, sm_buffer_begin(in), sm_buffer_length(in));
  uint8_t sgn[br_sha256_SIZE];
  br_sha256_out(&ctx, sgn);

  // From the documentation of the signature - we use the raw version of the
  // signature for JWT (apparently)
  sm_buffer_resize(sig, 64);
  const br_ec_impl *impl = br_ec_get_default();
  br_ecdsa_sign sign = br_ecdsa_sign_raw_get_default();
  size_t outlen =
      sign(impl, &br_sha256_vtable, sgn, &c->key, sm_buffer_begin(*sig));
  if (outlen == 0) {
    return false;
  }

  // Resize the buffer
  sm_buffer_resize(sig, outlen);

  return true;
}

static void free_ec_private_key(sm_ec_sign_ctx_ *c) { sm_free(c->key.x); }

const sm_sign_engine sm_es256_sign_vtable = {
    .context_size = sizeof(sm_es256_sign_ctx),
    .load_privkey = (void (*)(const sm_sign_engine **,
                              const sm_buffer))(&sm_ec_load_privkey),
    .sign = (bool (*)(const sm_sign_engine **, const sm_buffer,
                      sm_buffer *))(&sm_es256_sign),
    .cleanup = (void (*)(const sm_sign_engine **))(&free_ec_private_key),
};
