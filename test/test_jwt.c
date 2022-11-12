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

#include "resources.h"
#include "smithy/authn/jwt.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/filesystem.h"
#include "smithy/stdlib/memory.h"

void ec() {
  SM_INFO("Testing ES256...\n");
  SM_AUTO(sm_token) token;
  sm_token_init(ES256, &token);
  SM_AUTO(sm_sign_ctx) sign_engine;
  sm_es256_sign_init(&sign_engine);

  SM_AUTO(sm_buffer) keybuf = sm_empty_buffer;
  SM_AUTO(sm_file) *k = sm_open(TEST_RESOURCE("ec.pem"), "r");
  SM_ASSERT(k->read(k, &keybuf));

  sm_sign_engine_load_privkey(&sign_engine, keybuf);

  sm_token_add_string_claim(&token, "name", "John Doe");

  SM_AUTO(sm_buffer) ser = sm_empty_buffer;
  sm_token_serialize(&token, &sign_engine, &ser);

  // printf("%.*s\n", sm_buffer_length(&ser), sm_buffer_begin(&ser));

  SM_AUTO(sm_verify_ctx) verify_engine;
  sm_es256_verify_init(&verify_engine);

  SM_AUTO(sm_buffer) cert_buf = sm_empty_buffer;
  SM_AUTO(sm_file) *c = sm_open(TEST_RESOURCE("cert_ec.pem"), "r");
  SM_ASSERT(c->read(c, &cert_buf));

  SM_AUTO(sm_trust_store) trust_store;
  sm_trust_store_init(&trust_store);
  sm_add_trust_anchor(&trust_store, cert_buf);

  sm_certificate_chain chain;
  sm_certificate_chain_init(&chain, &trust_store, NULL);
  sm_add_pem_certificate_to_chain(&chain, cert_buf);
  SM_ASSERT(sm_finish_certificate_chain(&chain));

  SM_AUTO(sm_token) parsed;
  SM_ASSERT(sm_token_deserialize(&parsed, &verify_engine, &chain, ser));
  sm_certificate_chain_cleanup(&chain);

  // sm_token_print(parsed);

  SM_AUTO(sm_buffer) claim = sm_empty_buffer;
  sm_token_get_claim(&parsed, "name", &claim);
  sm_buffer correct = sm_buffer_alias_str("John Doe");
  SM_ASSERT(sm_buffer_equal(claim, correct));

  SM_INFO("successful\n");
}

void rsa() {
  SM_INFO("Testing RS256...\n");
  SM_AUTO(sm_token) token;
  sm_token_init(RS256, &token);
  SM_AUTO(sm_sign_ctx) sign_engine;
  sm_rs256_sign_init(&sign_engine);

  SM_AUTO(sm_buffer) keybuf = sm_empty_buffer;
  SM_AUTO(sm_file) *k = sm_open(TEST_RESOURCE("rsa.pem"), "r");
  SM_ASSERT(k->read(k, &keybuf));

  sm_sign_engine_load_privkey(&sign_engine, keybuf);

  sm_token_add_string_claim(&token, "name", "John Doe");

  SM_AUTO(sm_buffer) ser = sm_empty_buffer;
  sm_token_serialize(&token, &sign_engine, &ser);

  // printf("%.*s\n", sm_buffer_length(&ser), sm_buffer_begin(&ser));

  SM_AUTO(sm_verify_ctx) verify_engine;
  sm_rs256_verify_init(&verify_engine);

  SM_AUTO(sm_buffer) cert_buf = sm_empty_buffer;
  SM_AUTO(sm_file) *c = sm_open(TEST_RESOURCE("cert_rsa.pem"), "r");
  SM_ASSERT(c->read(c, &cert_buf));

  SM_AUTO(sm_trust_store) trust_store;
  sm_trust_store_init(&trust_store);
  sm_add_trust_anchor(&trust_store, cert_buf);

  sm_certificate_chain chain;
  sm_certificate_chain_init(&chain, &trust_store, NULL);
  sm_add_pem_certificate_to_chain(&chain, cert_buf);
  SM_ASSERT(sm_finish_certificate_chain(&chain));

  SM_AUTO(sm_token) parsed;
  SM_ASSERT(sm_token_deserialize(&parsed, &verify_engine, &chain, ser));
  sm_certificate_chain_cleanup(&chain);

  // sm_token_print(parsed);

  SM_AUTO(sm_buffer) claim = sm_empty_buffer;
  sm_token_get_claim(&parsed, "name", &claim);
  sm_buffer correct = sm_buffer_alias_str("John Doe");
  SM_ASSERT(sm_buffer_equal(claim, correct));

  SM_INFO("successful\n");
}

int main() {
  ec();
  rsa();
}
