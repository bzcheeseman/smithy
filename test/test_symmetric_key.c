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
#include "smithy/stdlib/buffer.h"

#include "resources.h"

void crypt(sm_buffer keybytes, sm_supported_symmetric algorithm) {
  sm_symmetric_key k;
  sm_symmetric_key_init(&k, algorithm, keybytes);

  SM_AUTO(sm_buffer) data = sm_empty_buffer;
  sm_buffer_resize(&data, 256);
  sm_buffer_fill_rand(data, sm_buffer_begin(data), sm_buffer_end(data));

  SM_AUTO(sm_buffer) check = sm_buffer_clone(data);
  SM_AUTO(sm_buffer) iv = sm_empty_buffer;
  sm_symmetric_encrypt(&k, &data, sm_empty_buffer, &iv);

  // Ensure the encryption changed the data
  sm_buffer msg_only =
      sm_buffer_alias(sm_buffer_begin(data), sm_buffer_length(data) - 16);
  SM_ASSERT(!sm_buffer_equal(check, data));
  SM_ASSERT(!sm_buffer_equal(check, msg_only));

  // And decrypt
  SM_ASSERT(sm_symmetric_decrypt(&k, &data, sm_empty_buffer, iv));
  // Make sure we got the right data
  SM_ASSERT(sm_buffer_equal(check, data));
}

void aes_128(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 16);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  crypt(keybytes, SM_AES_128_GCM);
}

void aes_128_fail(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 13);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  // Should fail because the key is too small
  sm_symmetric_key k;
  SM_INFO("Expected error: ");
  SM_ASSERT(!sm_symmetric_key_init(&k, SM_AES_128_GCM, keybytes));
}

void aes_192(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 24);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  crypt(keybytes, SM_AES_192_GCM);
}

void aes_192_fail(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 1213);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  // Should fail because the key is too big
  sm_symmetric_key k;
  SM_INFO("Expected error: ");
  SM_ASSERT(!sm_symmetric_key_init(&k, SM_AES_192_GCM, keybytes));
}

void aes_256(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 32);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  crypt(keybytes, SM_AES_256_GCM);
}

void aes_256_fail(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;

  // Should fail because the key is too small
  sm_symmetric_key k;
  SM_INFO("Expected error: ");
  SM_ASSERT(!sm_symmetric_key_init(&k, SM_AES_256_GCM, keybytes));
}

void chacha(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 32);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  crypt(keybytes, SM_CHACHA20_POLY1305);
}

void chacha_fail(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 31);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  // Should fail because the key is too small
  sm_symmetric_key k;
  SM_INFO("Expected error: ");
  SM_ASSERT(!sm_symmetric_key_init(&k, SM_CHACHA20_POLY1305, keybytes));
}

void newkey_aes_128(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 32);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  SM_AUTO(sm_buffer) extra_info = sm_empty_buffer;
  sm_buffer_resize(&extra_info, 12345);
  sm_buffer_fill_rand(extra_info, sm_buffer_begin(extra_info),
                      sm_buffer_end(extra_info));

  SM_AUTO(sm_buffer) newkey = sm_empty_buffer;
  sm_keybytes_from_master(keybytes, extra_info, SM_AES_128_GCM, &newkey);

  // The keys should NOT be the same
  SM_ASSERT(!sm_buffer_equal(keybytes, newkey));
  // The key length should be 16 bytes
  SM_ASSERT(newkey.length == 16);
}

void newkey_aes_192(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 32);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  SM_AUTO(sm_buffer) extra_info = sm_empty_buffer;
  sm_buffer_resize(&extra_info, 12345);
  sm_buffer_fill_rand(extra_info, sm_buffer_begin(extra_info),
                      sm_buffer_end(extra_info));

  SM_AUTO(sm_buffer) newkey = sm_empty_buffer;
  sm_keybytes_from_master(keybytes, extra_info, SM_AES_192_GCM, &newkey);

  // The keys should NOT be the same
  SM_ASSERT(!sm_buffer_equal(keybytes, newkey));
  // The key length should be 24 bytes
  SM_ASSERT(newkey.length == 24);
}

void newkey_aes_256(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 32);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  SM_AUTO(sm_buffer) extra_info = sm_empty_buffer;
  sm_buffer_resize(&extra_info, 12345);
  sm_buffer_fill_rand(extra_info, sm_buffer_begin(extra_info),
                      sm_buffer_end(extra_info));

  SM_AUTO(sm_buffer) newkey = sm_empty_buffer;
  sm_keybytes_from_master(keybytes, extra_info, SM_AES_256_GCM, &newkey);

  // The keys should NOT be the same
  SM_ASSERT(!sm_buffer_equal(keybytes, newkey));
  // The key length should be 32 bytes
  SM_ASSERT(newkey.length == 32);
}

void newkey_chacha(void) {
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_buffer_resize(&keybytes, 32);
  sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                      sm_buffer_end(keybytes));

  SM_AUTO(sm_buffer) extra_info = sm_empty_buffer;
  sm_buffer_resize(&extra_info, 12345);
  sm_buffer_fill_rand(extra_info, sm_buffer_begin(extra_info),
                      sm_buffer_end(extra_info));

  SM_AUTO(sm_buffer) newkey = sm_empty_buffer;
  sm_keybytes_from_master(keybytes, extra_info, SM_AES_256_GCM, &newkey);

  // The keys should NOT be the same
  SM_ASSERT(!sm_buffer_equal(keybytes, newkey));
  // The key length should be 32 bytes
  SM_ASSERT(newkey.length == 32);
}

void pbkdf_singleround(void) {
  const char *password = "password";
  const char *salt = "salt";
  sm_buffer saltbuf = sm_buffer_alias_str(salt);

  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_keybytes_from_password(sm_buffer_alias_str(password), 1, SM_AES_256_GCM,
                            &saltbuf, &keybytes);

  const uint8_t correct[] = {
      0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7,
      0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9,
  };
  sm_buffer correct_buf = sm_buffer_alias((uint8_t *)correct, sizeof(correct));
  sm_buffer test_buf =
      sm_buffer_alias(sm_buffer_begin(keybytes), sizeof(correct));
  SM_ASSERT(sm_buffer_equal(correct_buf, test_buf));
}

void pbkdf_hard(void) {
  const char *password = "passwordPASSWORDpassword";
  const char *salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
  sm_buffer saltbuf = sm_buffer_alias_str(salt);

  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_keybytes_from_password(sm_buffer_alias_str(password), 4096, SM_AES_256_GCM,
                            &saltbuf, &keybytes);

  const uint8_t correct[] = {
      0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32,
      0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf, 0x2b, 0x17,
      0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c,
  };
  sm_buffer correct_buf = sm_buffer_alias((uint8_t *)correct, sizeof(correct));
  sm_buffer test_buf =
      sm_buffer_alias(sm_buffer_begin(keybytes), sizeof(correct));
  SM_ASSERT(sm_buffer_equal(correct_buf, test_buf));
}

// This test is very slow, run it sparingly
void pbkdf_manyround(void) {
  const char *password = "password";
  const char *salt = "salt";
  sm_buffer saltbuf = sm_buffer_alias_str(salt);

  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  sm_keybytes_from_password(sm_buffer_alias_str(password), 16777216,
                            SM_AES_256_GCM, &saltbuf, &keybytes);

  const uint8_t correct[] = {
      0xcf, 0x81, 0xc6, 0x6f, 0xe8, 0xcf, 0xc0, 0x4d, 0x1f, 0x31,
      0xec, 0xb6, 0x5d, 0xab, 0x40, 0x89, 0xf7, 0xf1, 0x79, 0xe8,
  };
  sm_buffer correct_buf = sm_buffer_alias((uint8_t *)correct, sizeof(correct));
  sm_buffer test_buf =
      sm_buffer_alias(sm_buffer_begin(keybytes), sizeof(correct));
  SM_ASSERT(sm_buffer_equal(correct_buf, test_buf));
}

int main(void) {
  aes_128();
  aes_128_fail();
  aes_192();
  aes_192_fail();
  aes_256();
  aes_256_fail();
  chacha();
  chacha_fail();
  newkey_aes_128();
  newkey_aes_192();
  newkey_aes_256();
  newkey_chacha();
  pbkdf_singleround();
  pbkdf_hard();
#ifdef SM_SLOW_TESTS
  pbkdf_manyround();
#endif
}
