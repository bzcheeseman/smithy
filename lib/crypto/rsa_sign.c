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

void sm_rs256_sign_init(sm_sign_ctx *ctx) {
  ctx->vtable = &sm_rs256_sign_vtable;
}

static void sm_rsa_load_privkey(sm_rsa_sign_ctx_ *c, const sm_buffer key) {
  br_skey_decoder_context decoder_ctx;
  br_skey_decoder_init(&decoder_ctx);

  sm_load_privkey(key, &decoder_ctx);

  // Set up the engine's signing pkey
  int keyty = br_skey_decoder_key_type(&decoder_ctx);
  SM_ASSERT(keyty == BR_KEYTYPE_RSA &&
            "Cannot use non-RSA pkey for RSA signing context");
  // We have to do a deep copy, which requires introspection
  const br_rsa_private_key *pkey = br_skey_decoder_get_rsa(&decoder_ctx);
  c->key.n_bitlen = pkey->n_bitlen;
  c->key.p = sm_calloc(pkey->plen, 1);
  c->key.plen = pkey->plen;
  memcpy(c->key.p, pkey->p, pkey->plen);
  c->key.q = sm_calloc(pkey->qlen, 1);
  c->key.qlen = pkey->qlen;
  memcpy(c->key.q, pkey->q, pkey->qlen);
  c->key.dp = sm_calloc(pkey->dplen, 1);
  c->key.dplen = pkey->dplen;
  memcpy(c->key.dp, pkey->dp, pkey->dplen);
  c->key.dq = sm_calloc(pkey->dqlen, 1);
  c->key.dqlen = pkey->dqlen;
  memcpy(c->key.dq, pkey->dq, pkey->dqlen);
  c->key.iq = sm_calloc(pkey->iqlen, 1);
  c->key.iqlen = pkey->iqlen;
  memcpy(c->key.iq, pkey->iq, pkey->iqlen);
}

static bool sm_rs256_sign(sm_rs256_sign_ctx *c, const sm_buffer in,
                          sm_buffer *sig) {
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, sm_buffer_begin(in), sm_buffer_length(in));
  uint8_t sgn[br_sha256_SIZE];
  br_sha256_out(&ctx, sgn);

  sm_buffer_resize(sig, (c->key.n_bitlen + 7) / 8);
  br_rsa_pkcs1_sign sign = br_rsa_pkcs1_sign_get_default();
  if (1 != sign(BR_HASH_OID_SHA256, sgn, br_sha256_SIZE, &c->key,
                sm_buffer_begin(*sig))) {
    return false;
  }

  return true;
}

static void free_rsa_private_key(sm_rsa_sign_ctx_ *c) {
  sm_free(c->key.p);
  sm_free(c->key.q);
  sm_free(c->key.dp);
  sm_free(c->key.dq);
  sm_free(c->key.iq);
}

const sm_sign_engine sm_rs256_sign_vtable = {
    .context_size = sizeof(sm_rs256_sign_ctx),
    .load_privkey = (void (*)(const sm_sign_engine **,
                              const sm_buffer))(&sm_rsa_load_privkey),
    .sign = (bool (*)(const sm_sign_engine **, const sm_buffer,
                      sm_buffer *))(&sm_rs256_sign),
    .cleanup = (void (*)(const sm_sign_engine **))(&free_rsa_private_key)};
