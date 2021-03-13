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

#include "smithy/stdlib/buffer.h"

#include <bearssl.h>

typedef enum {
  SM_AES_128_GCM,
  SM_AES_192_GCM,
  SM_AES_256_GCM,
  SM_CHACHA20_POLY1305,
} sm_supported_symmetric;

typedef struct {
  sm_supported_symmetric algorithm;
  union {
    br_aes_ct64_ctr_keys aes;
    uint8_t chacha[32];
  } k;
} sm_symmetric_key;

// Returns true on success, false on failure. If false, the key is not valid for
// use.
bool sm_symmetric_key_init(sm_symmetric_key *key,
                           const sm_supported_symmetric algorithm,
                           const sm_buffer keybytes);

// Encrypts in-place
void sm_symmetric_encrypt(const sm_symmetric_key *key, sm_buffer *crypt,
                          const sm_buffer aad, sm_buffer *iv);
// Encrypts in-place
bool sm_symmetric_decrypt(const sm_symmetric_key *key, sm_buffer *crypt,
                          const sm_buffer aad, const sm_buffer iv);

// Takes a master key and some input bytes and deterministically produces a
// sub-key according to NIST SP 800-108. Here `input` is Label || 0x00 ||
// Context from the NIST specification. The rest is handled internally.
void sm_keybytes_from_master(const sm_buffer master, const sm_buffer input,
                             const sm_supported_symmetric algorithm,
                             sm_buffer *key);

// If `salt` is empty then it generates a salt and a new key. The key bytes are
// stored in `key`
void sm_keybytes_from_password(const sm_buffer password,
                               const size_t iterations,
                               const sm_supported_symmetric algorithm,
                               sm_buffer *salt, sm_buffer *key);
