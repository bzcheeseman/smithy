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

#include <bearssl.h>

#include "smithy/stdlib/buffer.h"

/// Enum of supported curves - this is basically limited by BearSSL and what it
/// supports.
typedef enum {
  SM_P256,
  SM_P384,
  SM_P521,
} sm_supported_curve;

/// Wrappers around the BearSSL key creation that allocates memory to hold the
/// various datastructures. For cases where more control over allocation is
/// required, use the br_ API instead.
bool sm_create_ec_keypair(sm_supported_curve curve, br_ec_private_key *priv,
                          br_ec_public_key *pub);
bool sm_create_rsa_keypair(uint16_t bits, br_rsa_private_key *priv,
                           br_rsa_public_key *pub);

/// Frees the memory allocated by creating a key pair. To free only one of the
/// two keys, pass in NULL for the other.
void sm_ec_keypair_cleanup(const br_ec_private_key *priv,
                           const br_ec_public_key *pub);
void sm_rsa_keypair_cleanup(const br_rsa_private_key *priv,
                            const br_rsa_public_key *pub);

/// Needed for the SM_AUTO macro.
static inline void free_br_ec_private_key(const br_ec_private_key *p) {
  sm_ec_keypair_cleanup(p, NULL);
}
static inline void free_br_ec_public_key(const br_ec_public_key *p) {
  sm_ec_keypair_cleanup(NULL, p);
}
static inline void free_br_rsa_private_key(const br_rsa_private_key *p) {
  sm_rsa_keypair_cleanup(p, NULL);
}
static inline void free_br_rsa_public_key(const br_rsa_public_key *p) {
  sm_rsa_keypair_cleanup(NULL, p);
}

/// Write a private key to `buf`. This DER-encodes the key, it does not PEM
/// encode it. To get PEM encoding, simply Base64 encode `buf`.
void sm_serialize_ec_privkey(const br_ec_private_key *key, sm_buffer *buf);
void sm_serialize_rsa_privkey(const br_rsa_private_key *key, sm_buffer *buf);

/// Write a public key to `buf`. This DER-encodes the key, it does not PEM
/// encode it. To get PEM encoding, simply Base64 encode `buf`.
void sm_serialize_ec_pubkey(const br_ec_public_key *key, sm_buffer *buf);
void sm_serialize_rsa_pubkey(const br_rsa_public_key *key, sm_buffer *buf);

/// Dumps the public key into a minimal, self-signed certificate. In order to
/// deserialize this certificate, its public key should also be added to the
/// cert_chain's trust store as a trust anchor. The certificate is in DER
/// format, to get PEM format just b64 encode.
bool sm_ec_pubkey_to_cert(const br_ec_private_key *priv,
                          const br_ec_public_key *pub, sm_buffer *buf);
bool sm_rsa_pubkey_to_cert(const br_rsa_private_key *priv,
                           const br_rsa_public_key *pub, sm_buffer *buf);

/// Creates a PEM-encoded CSR from the provided key and writes it into pembuf.
/// Parse the returned certificate with the br_x509 functions.
bool sm_ec_get_csr(const br_ec_private_key *priv, const br_ec_public_key *pub,
                   const sm_buffer org, const sm_buffer cn, sm_buffer *pembuf);
bool sm_rsa_get_csr(const br_rsa_private_key *priv,
                    const br_rsa_public_key *pub, const sm_buffer org,
                    const sm_buffer cn, sm_buffer *pembuf);

/// Performs an ECDH key exchange and returns a shared secret
bool sm_ec_keyx(const br_ec_private_key *me, const br_ec_public_key *peer,
                sm_buffer *shared_secret);
