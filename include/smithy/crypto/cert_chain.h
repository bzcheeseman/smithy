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

#include "smithy/crypto/trust_store.h"
#include "smithy/stdlib/buffer.h"

#include <stddef.h>

#include <bearssl.h>

/// The contents of this structure shall be considered opaque
typedef struct {
  br_x509_minimal_context ctx;
} sm_certificate_chain;

/**
 * From BearSSL:
 *
 * The `server_name`, if not `NULL`, will be considered as a
 * fully qualified domain name, to be matched against the `dNSName`
 * elements of the end-entity certificate's SAN extension (if there
 * is no SAN, then the Common Name from the subjectDN will be used).
 * If `server_name` is `NULL` then no such matching is performed.
 */
void sm_certificate_chain_init(sm_certificate_chain *chain, sm_trust_store *t,
                               const char *server_name);
/// Cleans up the chain.
void sm_certificate_chain_cleanup(const sm_certificate_chain *chain);

/// Add the given certificate to the chain. The PEM version may return false if
/// PEM decoding failed.
bool sm_add_pem_certificate_to_chain(sm_certificate_chain *chain,
                                     const sm_buffer pem);
void sm_add_der_certificate_to_chain(sm_certificate_chain *chain,
                                     const sm_buffer der);

/// Finish the certificate chain. This runs verification on the chain to ensure
/// the chain is valid. Returns true on success.
bool sm_finish_certificate_chain(sm_certificate_chain *chain);

/// Get the end-entity public key. `sm_finish_certificate_chain` must have
/// returned true for this to succeed.
const br_x509_pkey *sm_get_end_entity_key(const sm_certificate_chain *chain,
                                          unsigned *usage);
