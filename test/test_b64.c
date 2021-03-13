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

#include "smithy/stdlib/alloc.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/b64.h"
#include "smithy/stdlib/buffer.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void test_std_enc() {
  uint8_t testvecb64[] = "OUI0NDY4MDQtRDBBQS00RTVCLTgzMzUtMDYxNjhENzMzRjlCCg==";
  uint8_t testvec[] = "9B446804-D0AA-4E5B-8335-06168D733F9B\n";

  const sm_buffer b64_test_buf =
      sm_buffer_alias(testvecb64, sizeof(testvecb64) - 1);

  const sm_buffer test_buf = sm_buffer_alias(testvec, sizeof(testvec) - 1);

  SM_AUTO(sm_buffer) encoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_encode(SM_B64_STANDARD_ENCODING, test_buf, &encoded));
  SM_ASSERT(sm_buffer_equal(encoded, b64_test_buf));

  // Now decode the test vector
  SM_AUTO(sm_buffer) decoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_decode(SM_B64_STANDARD_ENCODING, encoded, &decoded));
  SM_ASSERT(sm_buffer_equal(decoded, test_buf));
}

void test_url_enc() {
  uint8_t testvecb64[] = "OUI0NDY4MDQtRDBBQS00RTVCLTgzMzUtMDYxNjhENzMzRjlCCg==";
  uint8_t testvec[] = "9B446804-D0AA-4E5B-8335-06168D733F9B\n";

  const sm_buffer b64_test_buf =
      sm_buffer_alias(testvecb64, sizeof(testvecb64) - 1);

  const sm_buffer test_buf = sm_buffer_alias(testvec, sizeof(testvec) - 1);

  SM_AUTO(sm_buffer) encoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_encode(SM_B64_URL_ENCODING, test_buf, &encoded));
  SM_ASSERT(sm_buffer_equal(encoded, b64_test_buf));

  // Now decode the test vector
  SM_AUTO(sm_buffer) decoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_decode(SM_B64_URL_ENCODING, encoded, &decoded));
  SM_ASSERT(sm_buffer_equal(decoded, test_buf));
}

void test_std_enc_nopad() {
  uint8_t testvecb64[] = "OUI0NDY4MDQtRDBBQS00RTVCLTgzMzUtMDYxNjhENzMzRjlCCg";
  uint8_t testvec[] = "9B446804-D0AA-4E5B-8335-06168D733F9B\n";

  const sm_buffer b64_test_buf =
      sm_buffer_alias(testvecb64, sizeof(testvecb64) - 1);

  const sm_buffer test_buf = sm_buffer_alias(testvec, sizeof(testvec) - 1);

  SM_AUTO(sm_buffer) encoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_encode(SM_B64_STANDARD_ENCODING_NOPAD, test_buf, &encoded));
  SM_ASSERT(sm_buffer_equal(encoded, b64_test_buf));

  // Now decode the test vector
  SM_AUTO(sm_buffer) decoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_decode(SM_B64_STANDARD_ENCODING_NOPAD, encoded, &decoded));
  SM_ASSERT(sm_buffer_equal(decoded, test_buf));
}

void test_url_enc_nopad() {
  uint8_t testvecb64[] = "OUI0NDY4MDQtRDBBQS00RTVCLTgzMzUtMDYxNjhENzMzRjlCCg";
  uint8_t testvec[] = "9B446804-D0AA-4E5B-8335-06168D733F9B\n";

  const sm_buffer b64_test_buf =
      sm_buffer_alias(testvecb64, sizeof(testvecb64) - 1);

  const sm_buffer test_buf = sm_buffer_alias(testvec, sizeof(testvec) - 1);

  SM_AUTO(sm_buffer) encoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_encode(SM_B64_URL_ENCODING_NOPAD, test_buf, &encoded));
  SM_ASSERT(sm_buffer_equal(encoded, b64_test_buf));

  // Now decode the test vector
  SM_AUTO(sm_buffer) decoded = sm_empty_buffer;

  SM_ASSERT(sm_b64_decode(SM_B64_URL_ENCODING_NOPAD, encoded, &decoded));
  SM_ASSERT(sm_buffer_equal(decoded, test_buf));
}

int main() {
  test_std_enc();
  test_url_enc();
  test_std_enc_nopad();
  test_url_enc_nopad();
}
