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

#include "smithy/crypto/symmetric_key.h"
#include "smithy/stdlib/memory.h"

#include <bearssl.h>

static void setup_aes_iv(sm_buffer *iv) {
  sm_buffer_resize(iv, 16);
  sm_buffer_fill_rand(*iv, sm_buffer_begin(*iv), sm_buffer_end(*iv));
}

static void aes_gcm_encrypt(const sm_symmetric_key *key, sm_buffer *crypt,
                            const sm_buffer aad, const sm_buffer iv) {
  br_gcm_context gcm_ctx;
  br_gcm_init(&gcm_ctx, (const br_block_ctr_class **)&key->k.aes,
              &br_ghash_ctmul64);

  // Setup the IV
  br_gcm_reset(&gcm_ctx, sm_buffer_begin(iv), sm_buffer_length(iv));
  // Inject AAD
  br_gcm_aad_inject(&gcm_ctx, sm_buffer_begin(aad), sm_buffer_length(aad));
  // Prepare for crypto
  br_gcm_flip(&gcm_ctx);

  // Do encryption - it's encrypted in place
  br_gcm_run(&gcm_ctx, 1, sm_buffer_begin(*crypt), sm_buffer_length(*crypt));
  // Save the current length
  size_t buflen = sm_buffer_length(*crypt);
  // Resize it to +16 bytes for the GCM tag
  sm_buffer_resize(crypt, sm_buffer_length(*crypt) + 16);
  // And put the tag in
  br_gcm_get_tag(&gcm_ctx, sm_buffer_begin(*crypt) + buflen);
}

static bool aes_gcm_decrypt(const sm_symmetric_key *key, sm_buffer *crypt,
                            const sm_buffer aad, const sm_buffer iv) {
  br_gcm_context gcm_ctx;
  br_gcm_init(&gcm_ctx, (const br_block_ctr_class **)&key->k.aes,
              &br_ghash_ctmul64);

  // Setup the IV (passed in)
  br_gcm_reset(&gcm_ctx, sm_buffer_begin(iv), sm_buffer_length(iv));
  // Inject AAD
  br_gcm_aad_inject(&gcm_ctx, sm_buffer_begin(aad), sm_buffer_length(aad));
  // Prepare for crypto
  br_gcm_flip(&gcm_ctx);

  // The encrypted buffer contains a 16-byte tag at the end
  size_t message_len = sm_buffer_length(*crypt) - 16;

  // Do decryption - it's decrypted in place
  br_gcm_run(&gcm_ctx, 0, sm_buffer_begin(*crypt), message_len);
  // Check the tag - 1 means exact match so anything other than 1 means failure
  if (1 != br_gcm_check_tag(&gcm_ctx, sm_buffer_begin(*crypt) + message_len)) {
    return false;
  }

  // Cut off the tag by setting that memory to 0, we don't need it anymore
  sm_memset(sm_buffer_begin(*crypt) + message_len, 0, 16);
  sm_buffer_resize(crypt, message_len);
  return true;
}

static void setup_chacha_iv(sm_buffer *iv) {
  sm_buffer_resize(iv, 12);
  sm_buffer_fill_rand(*iv, sm_buffer_begin(*iv), sm_buffer_end(*iv));
}

static void chacha20_poly1305_encrypt(const sm_symmetric_key *key,
                                      sm_buffer *crypt, const sm_buffer aad,
                                      const sm_buffer iv) {
  br_poly1305_run runner = br_poly1305_ctmulq_get();
  if (!runner) {
    runner = br_poly1305_ctmul_run;
  }

  br_chacha20_run chacha_impl = br_chacha20_sse2_get();
  if (!chacha_impl) {
    chacha_impl = br_chacha20_ct_run;
  }

  // Resize the crypt buffer to add space for the tag.
  size_t message_len = sm_buffer_length(*crypt);
  sm_buffer_resize(crypt, message_len + 16);

  runner(key->k.chacha, sm_buffer_begin(iv), sm_buffer_begin(*crypt),
         message_len, sm_buffer_begin(aad), sm_buffer_length(aad),
         sm_buffer_begin(*crypt) + message_len, chacha_impl, 1);
}

static bool chacha20_poly1305_decrypt(const sm_symmetric_key *key,
                                      sm_buffer *crypt, const sm_buffer aad,
                                      const sm_buffer iv) {
  br_poly1305_run runner = br_poly1305_ctmulq_get();
  if (!runner) {
    runner = br_poly1305_ctmul_run;
  }

  br_chacha20_run chacha_impl = br_chacha20_sse2_get();
  if (!chacha_impl) {
    chacha_impl = br_chacha20_ct_run;
  }

  // The crypt buffer holds the encrypted data and a tag
  size_t message_len = sm_buffer_length(*crypt) - 16;

  // Get a buffer for the tag
  SM_AUTO(sm_buffer) tagbuf = sm_empty_buffer;
  sm_buffer_resize(&tagbuf, 16);

  // After this completes, we have to check the tag for equality
  runner(key->k.chacha, sm_buffer_begin(iv), sm_buffer_begin(*crypt),
         message_len, sm_buffer_begin(aad), sm_buffer_length(aad),
         sm_buffer_begin(tagbuf), chacha_impl, 0);

  // The return value of decrypt is just the value of "is the computed tag
  // exactly equal to the old tag"
  sm_buffer old_tag_alias =
      sm_buffer_alias(sm_buffer_begin(*crypt) + message_len, 16);
  if (!sm_buffer_equal(tagbuf, old_tag_alias)) {
    return false;
  }

  // Cut off the tag by setting that memory to 0, we don't need it anymore
  sm_memset(sm_buffer_begin(*crypt) + message_len, 0, 16);
  sm_buffer_resize(crypt, message_len);
  return true;
}

static size_t get_key_size_bytes(const sm_supported_symmetric algorithm) {
  switch (algorithm) {
  case SM_AES_128_GCM:
    return 16;
  case SM_AES_192_GCM:
    return 24;
  case SM_AES_256_GCM: // fallthrough
  case SM_CHACHA20_POLY1305:
    return 32;
  default:
    break;
  }
  return SIZE_MAX;
}

void sm_generate_iv(const sm_symmetric_key *key, sm_buffer *iv) {
  switch (key->algorithm) {
  case SM_AES_128_GCM:
  case SM_AES_192_GCM:
  case SM_AES_256_GCM:
    setup_aes_iv(iv);
    break;
  case SM_CHACHA20_POLY1305:
    setup_chacha_iv(iv);
    break;
  }
}

bool sm_symmetric_key_init(sm_symmetric_key *key,
                           const sm_supported_symmetric algorithm,
                           const sm_buffer keybytes) {
  key->algorithm = algorithm;
  const size_t required_key_size = get_key_size_bytes(algorithm);
  if (required_key_size == SIZE_MAX) {
    SM_ERROR("Could not find the required key size for algorithm: %d\n",
             algorithm);
    return false;
  }
  if (sm_buffer_length(keybytes) != required_key_size) {
    SM_ERROR("Expected %zu byte key, received %zu byte key\n",
             required_key_size, sm_buffer_length(keybytes));
    return false;
  }

  switch (algorithm) {
  case SM_AES_128_GCM: // fallthrough
  case SM_AES_192_GCM: // fallthrough
  case SM_AES_256_GCM: {
    br_aes_ct64_ctr_init(&key->k.aes, sm_buffer_begin(keybytes),
                         sm_buffer_length(keybytes));
    return true;
  }
  case SM_CHACHA20_POLY1305: {
    memcpy(key->k.chacha, sm_buffer_begin(keybytes), 32);
    return true;
  }
  default:
    break;
  }

  SM_ERROR("Unknown symmetric encryption algorithm\n");
  return false;
}

void sm_symmetric_encrypt(const sm_symmetric_key *key, sm_buffer *crypt,
                          const sm_buffer aad, const sm_buffer iv) {
  switch (key->algorithm) {
  case SM_AES_128_GCM: // fallthrough
  case SM_AES_192_GCM: // fallthrough
  case SM_AES_256_GCM: {
    aes_gcm_encrypt(key, crypt, aad, iv);
    return;
  }
  case SM_CHACHA20_POLY1305: {
    chacha20_poly1305_encrypt(key, crypt, aad, iv);
    return;
  }
  }
}

bool sm_symmetric_decrypt(const sm_symmetric_key *key, sm_buffer *crypt,
                          const sm_buffer aad, const sm_buffer iv) {
  switch (key->algorithm) {
  case SM_AES_128_GCM: // fallthrough
  case SM_AES_192_GCM: // fallthrough
  case SM_AES_256_GCM: {
    return aes_gcm_decrypt(key, crypt, aad, iv);
  }
  case SM_CHACHA20_POLY1305: {
    return chacha20_poly1305_decrypt(key, crypt, aad, iv);
  }
  }
}

// Here `input` is Label || 0x00 || Context from the NIST specification - we
// handle other concatenation
void sm_keybytes_from_master(const sm_buffer master, const sm_buffer input,
                             const sm_supported_symmetric algorithm,
                             sm_buffer *key) {
  // digest length in bytes - we always use SHA-256
  size_t digestbytes = 32;
  // digestlen should be in bits
  size_t digestbits = digestbytes * 8;

  // Get the number of bits required for the key
  uint32_t keybytes = get_key_size_bytes(algorithm);
  uint32_t keybits = keybytes * 8;

  // Number of times to perform the HMAC operation
  size_t rounds = keybits / digestbits + (keybits % digestbits != 0);

  // The input to the HMAC
  size_t input_bytes_len =
      sizeof(uint32_t) + sm_buffer_length(input) + sizeof(uint32_t);
  uint8_t input_bytes[input_bytes_len];

  // Copy over the input data and the desired key bits (NIST SP 800-108)
  memcpy(input_bytes + sizeof(uint32_t), sm_buffer_begin(input),
         sm_buffer_length(input));
  memcpy(input_bytes + sizeof(uint32_t) + sm_buffer_length(input), &keybits,
         sizeof(uint32_t));

  // Get the data out of the master key for the HMAC
  const size_t master_keylen = sm_buffer_length(master);
  const uint8_t *master_key_bytes = sm_buffer_begin(master);

  // Setup the key context
  br_hmac_key_context hmac_key_ctx;
  br_hmac_key_init(&hmac_key_ctx, &br_sha256_vtable, master_key_bytes,
                   master_keylen);

  br_hmac_context hmac_ctx;
  br_hmac_init(&hmac_ctx, &hmac_key_ctx, 0);

  // Allocate the correct amount of memory for the output bytes
  uint8_t output_bytes[rounds * digestbytes];
  for (size_t i = 0; i < rounds; ++i) {
    // Copy over the count (NIST SP 800-108)
    memcpy(input_bytes, &i, sizeof(uint32_t));

    // Do the HMAC - and write the hmac output into the correct place in the
    // output
    size_t bytes =
        br_hmac_outCT(&hmac_ctx, input_bytes, input_bytes_len, input_bytes_len,
                      input_bytes_len, output_bytes + (i * digestbytes));
    SM_ASSERT(bytes == digestbytes);
  }

  // The output is the leftmost L bits of result(n)
  uint8_t *out_bytes = output_bytes + ((rounds - 1) * digestbytes);

  // Get the first keylen bytes and use them for the key
  sm_buffer_insert(key, sm_buffer_begin(*key), out_bytes, out_bytes + keybytes);
}

void sm_keybytes_from_password(const sm_buffer password,
                               const size_t iterations,
                               const sm_supported_symmetric algorithm,
                               sm_buffer *salt, sm_buffer *key) {
  const size_t keybytes = get_key_size_bytes(algorithm);
  // keybytes will always be <= 32 bytes, which is the output of the
  // SHA-256 hash function, so given this
  // DK = T_1 + T_2 + ... + T_{dklen/hlen}
  // We can simplify to DK = T1 since dklen/hlen <= 1
  SM_ASSERT(keybytes <= 32);

  const size_t password_len = sm_buffer_length(password);
  const uint8_t *password_bytes = sm_buffer_begin(password);

  // Set up the key ctx - always use SHA-256
  br_hmac_key_context hmac_key_ctx;
  br_hmac_key_init(&hmac_key_ctx, &br_sha256_vtable, password_bytes,
                   password_len);

  // Set up the hmac ctx
  br_hmac_context hmac_ctx;
  br_hmac_init(&hmac_ctx, &hmac_key_ctx, 0);

  // The basic PBKDF function is this:
  // T_i = F(Password, Salt, c, i)
  // F(Password, Salt, c, i) = U_1 ^ U_2 ^ ⋯ ^ U_c
  // U_1 = PRF(Password, Salt + INT_32_BE(i))
  // ...
  // U_c = PRF(Password, U_{c−1})

  // Construct U_0
  if (sm_buffer_empty(*salt)) {
    // NIST recommends a salt of at least 16 bytes
    sm_buffer_resize(salt, 32);
    sm_buffer_fill_rand(*salt, sm_buffer_begin(*salt), sm_buffer_end(*salt));
  }

  // This is U_0
  SM_AUTO(sm_buffer) u_0 = sm_buffer_clone(*salt);
  // Insert big-endian 1 (i is a 1-based index)
  uint32_t one = htonl(1);
  sm_buffer_insert(&u_0, sm_buffer_end(u_0), (uint8_t *)&one,
                   (uint8_t *)&one + sizeof(uint32_t));

  uint8_t u_left[32];
  uint8_t u_right[32];
  uint8_t f_buf[32];

  // Do the first hmac and output into U_1
  br_hmac_outCT(&hmac_ctx, sm_buffer_begin(u_0), sm_buffer_length(u_0),
                sm_buffer_length(u_0), sm_buffer_length(u_0), u_left);

  // Single iteration
  if (iterations == 1) {
    sm_buffer_insert(key, sm_buffer_begin(*key), u_left, u_left + 32);
    return;
  }

  uint8_t *u_input = u_left;
  uint8_t *u_output = u_right;
  // Copy U_1 into the final buffer
  memcpy(f_buf, u_input, 32);
  for (size_t i = 1; i < iterations; ++i) {
    // Do the hmac, taking from the previous and placing it into the current
    // one.
    br_hmac_outCT(&hmac_ctx, u_input, 32, 32, 32, u_output);

    // Collect the output into f_buf with the xors
    uint64_t *f_64b = (uint64_t *)f_buf;
    uint64_t *u_64b = (uint64_t *)u_output;
    f_64b[0] = f_64b[0] ^ u_64b[0];
    f_64b[1] = f_64b[1] ^ u_64b[1];
    f_64b[2] = f_64b[2] ^ u_64b[2];
    f_64b[3] = f_64b[3] ^ u_64b[3];

    // Swap input and output
    uint8_t *tmp = u_output;
    u_output = u_input;
    u_input =
        tmp; // the input to the next round is just the output of this round
  }

  sm_buffer_insert(key, sm_buffer_begin(*key), (uint8_t *)&f_buf,
                   (uint8_t *)&f_buf + 32);
}
