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

#include "resources.h"
#include "smithy/crypto/cert_chain.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/filesystem.h"

void ec() {
  SM_AUTO(sm_buffer) cert_buf = sm_empty_buffer;
  SM_AUTO(sm_file) *cert = sm_open(TEST_RESOURCE("cert_ec.pem"), "r");
  SM_ASSERT(cert->read(cert, &cert_buf));

  // Add the trust anchor
  SM_AUTO(sm_trust_store) trust_store;
  sm_trust_store_init(&trust_store);
  sm_add_trust_anchor(&trust_store, cert_buf);

  // Setup the certificate chain
  sm_certificate_chain chain;
  sm_certificate_chain_init(&chain, &trust_store, NULL);

  // Add the certificate (same cert)
  sm_add_pem_certificate_to_chain(&chain, cert_buf);
  // This must succeed - it's the same cert as the trust anchor
  SM_ASSERT(sm_finish_certificate_chain(&chain));

  sm_certificate_chain_cleanup(&chain);
}

void rsa() {
  SM_AUTO(sm_buffer) cert_buf = sm_empty_buffer;
  SM_AUTO(sm_file) *cert = sm_open(TEST_RESOURCE("cert_rsa.pem"), "r");
  SM_ASSERT(cert->read(cert, &cert_buf));

  // Add the trust anchor
  SM_AUTO(sm_trust_store) trust_store;
  sm_trust_store_init(&trust_store);
  sm_add_trust_anchor(&trust_store, cert_buf);

  // Setup the certificate chain
  sm_certificate_chain chain;
  sm_certificate_chain_init(&chain, &trust_store, NULL);

  // Add the certificate (same cert)
  sm_add_pem_certificate_to_chain(&chain, cert_buf);
  // This must succeed - it's the same cert as the trust anchor
  SM_ASSERT(sm_finish_certificate_chain(&chain));

  sm_certificate_chain_cleanup(&chain);
}

void fail() {
  SM_AUTO(sm_buffer) cert_buf = sm_empty_buffer;
  SM_AUTO(sm_file) *cert = sm_open(TEST_RESOURCE("cert_ec.pem"), "r");
  SM_ASSERT(cert->read(cert, &cert_buf));

  SM_AUTO(sm_buffer) rsa_buf = sm_empty_buffer;
  SM_AUTO(sm_file) *rsa = sm_open(TEST_RESOURCE("cert_rsa.pem"), "r");
  SM_ASSERT(rsa->read(rsa, &rsa_buf));

  // Add the trust anchor
  SM_AUTO(sm_trust_store) trust_store;
  sm_trust_store_init(&trust_store);
  sm_add_trust_anchor(&trust_store, cert_buf);

  // Setup the certificate chain
  sm_certificate_chain chain;
  sm_certificate_chain_init(&chain, &trust_store, NULL);

  // Add the certificate (same cert)
  sm_add_pem_certificate_to_chain(&chain, rsa_buf);
  // This must not succeed - totally different certificates
  SM_ASSERT(sm_finish_certificate_chain(&chain) == false);

  sm_certificate_chain_cleanup(&chain);
}

int main() {
  ec();
  rsa();
  fail();
}
