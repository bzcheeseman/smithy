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

/// Encrypts `buf` with `pub` and places the result in `ciphertext`. `label`
/// optionally contains data that should be bound to the ciphertext but that
/// does NOT need to be encrypted.
bool sm_rsa_encrypt(const br_rsa_public_key *pub, const sm_buffer buf,
                    const sm_buffer label, sm_buffer *ciphertext);

/// Decrypts `ciphertext` in-place with `priv`. `label` optionally contains data
/// that should be bound to the ciphertext but that does NOT need to be
/// encrypted. It must be the same value passed into the encrypt method.
bool sm_rsa_decrypt(const br_rsa_private_key *priv, sm_buffer *crypt,
                    const sm_buffer label);

//=====-----------------------------------------------------------------=====//
// Type-generic Asymmetric Encrypt/Decrypt
//=====-----------------------------------------------------------------=====//

/// Tagged union that contains either an EC key or a RSA private key.
typedef struct {
  union {
    br_rsa_private_key rsa;
    br_ec_private_key ec;
  };
  /// This field is either BR_KEYTYPE_RSA or BR_KEYTYPE_EC.
  uint8_t kind;
} sm_asymmetric_private_key;

/// Needed for the SM_AUTO macro.
static inline void
free_sm_asymmetric_private_key(const sm_asymmetric_private_key *p) {
  if (p->kind == BR_KEYTYPE_EC)
    sm_ec_keypair_cleanup(&p->ec, NULL);
  else
    sm_rsa_keypair_cleanup(&p->rsa, NULL);
}

/// Tagged union that contains either an EC key or a RSA public key.
typedef struct {
  union {
    br_rsa_public_key rsa;
    br_ec_public_key ec;
  };
  /// This field is either BR_KEYTYPE_RSA or BR_KEYTYPE_EC.
  uint8_t kind;
} sm_asymmetric_public_key;

/// Needed for the SM_AUTO macro.
static inline void
free_sm_asymmetric_public_key(const sm_asymmetric_public_key *p) {
  if (p->kind == BR_KEYTYPE_EC)
    sm_ec_keypair_cleanup(NULL, &p->ec);
  else
    sm_rsa_keypair_cleanup(NULL, &p->rsa);
}

/// Create an asymmetric keypair. If `bits_or_curve` is less than 2048 then it's
/// assumed to be a curve - one of {SM_P256 == 0, SM_P384 == 1, SM_P521 == 2},
/// to be exact.
bool sm_create_asymmetric_keypair(uint16_t bits_or_curve,
                                  sm_asymmetric_private_key *priv,
                                  sm_asymmetric_public_key *pub);

/// Type-generic encryption for a given asymmetric key. This function internally
/// uses what OpenSSL calls 'envelope' encryption, which means that it always
/// generates a symmetric key and encrypts the data with that symmetric key. For
/// EC keys, it uses `sm_ec_keyx` above to compute a shared secret, then passes
/// that through a PBKDF. The salt is placed into the AAD buffer along with the
/// IV used for the actual data encryption. For RSA keys, a new key is generated
/// from random bytes and encrypted with the public key of the peer. That
/// encrypted key is added to the AAD buffer, along with the IV used for the
/// actual data encryption. The user may provide any AAD required - this
/// function will write the additional data needed for decryption
/// (salt/encrypted key and IV) to the beginning of the buffer in DER-encoded
/// form.
bool sm_asymmetric_encrypt(sm_asymmetric_private_key *me,
                           sm_asymmetric_public_key *peer,
                           const sm_buffer plaintext, sm_buffer *ciphertext,
                           sm_buffer *aad);

/// Type-generic decryption for a given asymmetric key. This function will
/// unwrap the AAD in order to perform decryption - either computing the shared
/// secret and computing the PBKDF for EC keys, or reading and decrypting the
/// encrypted symmetric key. This function modifies `aad` to strip out the
/// additional data added by the encryption function, to ensure the user is able
/// to recover their data exactly.
bool sm_asymmetric_decrypt(sm_asymmetric_private_key *me,
                           sm_asymmetric_public_key *peer,
                           const sm_buffer ciphertext, sm_buffer *aad,
                           sm_buffer *plaintext);
