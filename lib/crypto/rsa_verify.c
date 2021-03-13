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
#include "smithy/stdlib/assert.h"

#include <bearssl.h>

void sm_rs256_verify_init(sm_verify_ctx *ctx) {
  ctx->vtable = &sm_rs256_verify_vtable;
}

static bool sm_rs256_verify(const sm_rs256_verify_ctx *c, const sm_buffer in,
                            const sm_buffer sig,
                            const sm_certificate_chain *chain) {
  (void)c;

  unsigned usage;
  const br_x509_pkey *pkey = sm_get_end_entity_key(chain, &usage);
  if (!pkey) {
    SM_ERROR("Unable to get the public key of the end entity certificate\n");
    return false;
  }
  SM_ASSERT(usage & BR_KEYTYPE_SIGN);

  br_sha256_context sha256_ctx;
  br_sha256_init(&sha256_ctx);
  br_sha256_update(&sha256_ctx, sm_buffer_begin(in), sm_buffer_length(in));
  uint8_t in_hash[br_sha256_SIZE];
  br_sha256_out(&sha256_ctx, in_hash);

  uint8_t hash[br_sha256_SIZE];
  br_rsa_pkcs1_vrfy verify = br_rsa_pkcs1_vrfy_get_default();
  if (1 != verify(sm_buffer_begin(sig), sm_buffer_length(sig),
                  BR_HASH_OID_SHA256, br_sha256_SIZE, &(pkey->key.rsa), hash)) {
    return false;
  }

  // Compare hash with in_hash
  sm_buffer ihash = sm_buffer_alias(in_hash, br_sha256_SIZE);
  sm_buffer ohash = sm_buffer_alias(hash, br_sha256_SIZE);
  // sm_buffer_equal is constant-time memcmp
  return sm_buffer_equal(ihash, ohash);
}

static void cleanup(const sm_rs256_verify_ctx *c) { (void)c; }

const sm_verify_engine sm_rs256_verify_vtable = {
    .context_size = sizeof(sm_rs256_verify_ctx),
    .verify =
        (bool (*)(const sm_verify_engine **, const sm_buffer, const sm_buffer,
                  const sm_certificate_chain *))(&sm_rs256_verify),
    .cleanup = (void (*)(const sm_verify_engine **))(&cleanup),
};
