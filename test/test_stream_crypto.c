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

#include "smithy/crypto/stream.h"

void simple(void) {
  // Set up a symmetric key.
  SM_AUTO(sm_buffer) key = sm_empty_buffer;
  sm_buffer_resize(&key, 32);
  sm_buffer_fill_rand(key, sm_buffer_begin(key), sm_buffer_end(key));

  sm_symmetric_key symm_key;
  sm_symmetric_key_init(&symm_key, SM_CHACHA20_POLY1305, key);

  SM_AUTO(sm_stream_ctx) ctx;
  sm_stream_ctx_init(&ctx, symm_key);

  SM_AUTO(sm_buffer) message = sm_empty_buffer;
  sm_buffer_resize(&message, 256);
  sm_buffer_fill_rand(message, sm_buffer_begin(message),
                      sm_buffer_end(message));

  SM_AUTO(sm_buffer) copy = sm_buffer_clone(message);

  // Ensure encryption does something.
  for (size_t i = 0; i < 256; i += 64) {
    sm_buffer alias = sm_buffer_alias(sm_buffer_begin(message) + i, 64);
    sm_stream_encrypt(&ctx, alias);
    sm_buffer copy_alias = sm_buffer_alias(sm_buffer_begin(copy) + i, 64);
    // Encryption happens in-place.
    SM_ASSERT(!sm_buffer_equal(alias, copy_alias));
  }

  // Ensure decryption works for the whole buffer.
  bool decrypted = sm_stream_decrypt(&ctx, message, 0);
  SM_ASSERT(decrypted && sm_buffer_equal(message, copy));
}

void decrypt_mid_stream(void) {
  // Set up a symmetric key.
  SM_AUTO(sm_buffer) key = sm_empty_buffer;
  sm_buffer_resize(&key, 32);
  sm_buffer_fill_rand(key, sm_buffer_begin(key), sm_buffer_end(key));

  sm_symmetric_key symm_key;
  sm_symmetric_key_init(&symm_key, SM_CHACHA20_POLY1305, key);

  SM_AUTO(sm_stream_ctx) ctx;
  sm_stream_ctx_init(&ctx, symm_key);

  SM_AUTO(sm_buffer) message = sm_empty_buffer;
  sm_buffer_resize(&message, 256);
  sm_buffer_fill_rand(message, sm_buffer_begin(message),
                      sm_buffer_end(message));

  SM_AUTO(sm_buffer) copy = sm_buffer_clone(message);

  // Ensure encryption does something.
  for (size_t i = 0; i < 256; i += 64) {
    sm_buffer alias = sm_buffer_alias(sm_buffer_begin(message) + i, 64);
    sm_stream_encrypt(&ctx, alias);
    sm_buffer copy_alias = sm_buffer_alias(sm_buffer_begin(copy) + i, 64);
    // Encryption happens in-place.
    SM_ASSERT(!sm_buffer_equal(alias, copy_alias));
  }

  // Decrypt more than 1 block in the middle.
  sm_buffer copy_alias = sm_buffer_alias(sm_buffer_begin(copy) + 79, 68);
  sm_buffer decrypt_alias = sm_buffer_alias(sm_buffer_begin(message) + 79, 68);
  bool decrypt = sm_stream_decrypt(&ctx, decrypt_alias, 79);
  SM_ASSERT(decrypt && sm_buffer_equal(decrypt_alias, copy_alias));
}

void small(void) {
  // Set up a symmetric key.
  SM_AUTO(sm_buffer) key = sm_empty_buffer;
  sm_buffer_resize(&key, 32);
  sm_buffer_fill_rand(key, sm_buffer_begin(key), sm_buffer_end(key));

  sm_symmetric_key symm_key;
  sm_symmetric_key_init(&symm_key, SM_CHACHA20_POLY1305, key);

  SM_AUTO(sm_stream_ctx) ctx;
  sm_stream_ctx_init(&ctx, symm_key);

  SM_AUTO(sm_buffer) message = sm_empty_buffer;
  sm_buffer_resize(&message, 13);
  sm_buffer_fill_rand(message, sm_buffer_begin(message),
                      sm_buffer_end(message));

  SM_AUTO(sm_buffer) copy = sm_buffer_clone(message);

  sm_stream_encrypt(&ctx, message);

  // Ensure decryption works for the whole buffer.
  bool decrypted = sm_stream_decrypt(&ctx, message, 0);
  SM_ASSERT(decrypted && sm_buffer_equal(message, copy));
}

void small_decrypt(void) {
  // Set up a symmetric key.
  SM_AUTO(sm_buffer) key = sm_empty_buffer;
  sm_buffer_resize(&key, 32);
  sm_buffer_fill_rand(key, sm_buffer_begin(key), sm_buffer_end(key));

  sm_symmetric_key symm_key;
  sm_symmetric_key_init(&symm_key, SM_CHACHA20_POLY1305, key);

  SM_AUTO(sm_stream_ctx) ctx;
  sm_stream_ctx_init(&ctx, symm_key);

  SM_AUTO(sm_buffer) message = sm_empty_buffer;
  sm_buffer_resize(&message, 256);
  sm_buffer_fill_rand(message, sm_buffer_begin(message),
                      sm_buffer_end(message));

  SM_AUTO(sm_buffer) copy = sm_buffer_clone(message);

  sm_stream_encrypt(&ctx, message);

  // Decrypt just a few bytes in the middle.
  sm_buffer copy_alias = sm_buffer_alias(sm_buffer_begin(copy) + 79, 3);
  sm_buffer alias = sm_buffer_alias(sm_buffer_begin(message) + 79, 3);
  bool decrypted = sm_stream_decrypt(&ctx, alias, 79);
  SM_ASSERT(decrypted && sm_buffer_equal(alias, copy_alias));
}

void simple_aes(void) {
  // Set up a symmetric key.
  SM_AUTO(sm_buffer) key = sm_empty_buffer;
  sm_buffer_resize(&key, 32);
  sm_buffer_fill_rand(key, sm_buffer_begin(key), sm_buffer_end(key));

  sm_symmetric_key symm_key;
  sm_symmetric_key_init(&symm_key, SM_AES_256_GCM, key);

  SM_AUTO(sm_stream_ctx) ctx;
  sm_stream_ctx_init(&ctx, symm_key);

  SM_AUTO(sm_buffer) message = sm_empty_buffer;
  sm_buffer_resize(&message, 256);
  sm_buffer_fill_rand(message, sm_buffer_begin(message),
                      sm_buffer_end(message));

  SM_AUTO(sm_buffer) copy = sm_buffer_clone(message);

  // Ensure encryption does something.
  for (size_t i = 0; i < 256; i += 64) {
    sm_buffer alias = sm_buffer_alias(sm_buffer_begin(message) + i, 64);
    sm_stream_encrypt(&ctx, alias);
    sm_buffer copy_alias = sm_buffer_alias(sm_buffer_begin(copy) + i, 64);
    // Encryption happens in-place.
    SM_ASSERT(!sm_buffer_equal(alias, copy_alias));
  }

  // Ensure decryption works for the whole buffer.
  bool decrypted = sm_stream_decrypt(&ctx, message, 0);
  SM_ASSERT(decrypted && sm_buffer_equal(message, copy));
}

void decrypt_mid_stream_aes(sm_supported_symmetric alg) {
  // Set up a symmetric key.
  SM_AUTO(sm_buffer) key = sm_empty_buffer;
  switch (alg) {
  case SM_AES_128_GCM:
    sm_buffer_resize(&key, 16);
    break;
  case SM_AES_192_GCM:
    sm_buffer_resize(&key, 24);
    break;
  case SM_AES_256_GCM:
    sm_buffer_resize(&key, 32);
    break;
  case SM_CHACHA20_POLY1305:
    SM_ASSERT(false);
  }
  sm_buffer_fill_rand(key, sm_buffer_begin(key), sm_buffer_end(key));

  sm_symmetric_key symm_key;
  sm_symmetric_key_init(&symm_key, alg, key);

  SM_AUTO(sm_stream_ctx) ctx;
  sm_stream_ctx_init(&ctx, symm_key);

  SM_AUTO(sm_buffer) message = sm_empty_buffer;
  sm_buffer_resize(&message, 256);
  sm_buffer_fill_rand(message, sm_buffer_begin(message),
                      sm_buffer_end(message));

  SM_AUTO(sm_buffer) copy = sm_buffer_clone(message);

  // Ensure encryption does something.
  for (size_t i = 0; i < 256; i += 64) {
    sm_buffer alias = sm_buffer_alias(sm_buffer_begin(message) + i, 64);
    sm_stream_encrypt(&ctx, alias);
    sm_buffer copy_alias = sm_buffer_alias(sm_buffer_begin(copy) + i, 64);
    // Encryption happens in-place.
    SM_ASSERT(!sm_buffer_equal(alias, copy_alias));
  }

  // Decrypt a more than 1 block in the middle.
  sm_buffer copy_alias = sm_buffer_alias(sm_buffer_begin(copy) + 79, 68);
  sm_buffer alias = sm_buffer_alias(sm_buffer_begin(message) + 79, 68);
  bool decrypt = sm_stream_decrypt(&ctx, alias, 79);
  SM_ASSERT(decrypt && sm_buffer_equal(alias, copy_alias));
}

int main(void) {
  simple();
  decrypt_mid_stream();
  small();
  small_decrypt();
  simple_aes();

  // Test AES implementations
  for (sm_supported_symmetric alg = SM_AES_128_GCM; alg <= SM_AES_256_GCM;
       ++alg) {
    decrypt_mid_stream_aes(alg);
  }
}
