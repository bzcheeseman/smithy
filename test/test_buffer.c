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
#include "smithy/stdlib/buffer.h"

#include <memory.h>
#include <stdlib.h>

int main() {
  SM_AUTO(sm_buffer) test_buf = sm_empty_buffer;
  SM_ASSERT(sm_buffer_empty(test_buf));

  sm_buffer_push(&test_buf, 0x9);
  SM_ASSERT(sm_buffer_length(test_buf) == 1);
  SM_ASSERT(*sm_buffer_begin(test_buf) == 0x9);

  sm_buffer_resize(&test_buf, 100);
  SM_ASSERT(sm_buffer_length(test_buf) == 100);
  // Fill the last 99 elements with random numbers
  arc4random_buf(sm_buffer_begin(test_buf) + 1, 99);

  // Make sure copy works the way we think it does
  SM_AUTO(sm_buffer) copy = sm_empty_buffer;
  sm_buffer_insert(&copy, sm_buffer_end(copy), sm_buffer_begin(test_buf),
                   sm_buffer_end(test_buf));
  SM_ASSERT(sm_buffer_equal(copy, test_buf));

  // Make sure the first element is still 0x9
  SM_ASSERT(*sm_buffer_begin(test_buf) == 0x9);

  sm_buffer_clear(&test_buf);
  SM_ASSERT(sm_buffer_empty(test_buf));

  sm_buffer_reserve(&test_buf, 35);
  SM_ASSERT(sm_buffer_empty(test_buf));

  uint8_t testdata[] = {0, 0, 9, 8, 7, 6, 5};
  const sm_buffer tdbuf = sm_buffer_alias(testdata, sizeof(testdata));
  SM_ASSERT(sm_buffer_begin(tdbuf) == &testdata[0]);
  SM_ASSERT(sm_buffer_end(tdbuf) == &testdata[sizeof(testdata)]);

  free_sm_buffer(&test_buf);
  memset(&test_buf, 0, sizeof(sm_buffer));
  sm_buffer_insert(&test_buf, sm_buffer_end(test_buf), testdata,
                   testdata + sizeof(testdata));
  SM_ASSERT(sm_buffer_equal(tdbuf, test_buf));

  // Insert some elements into the beginning of the buffer
  sm_buffer_insert(&test_buf, sm_buffer_begin(test_buf) + 2, testdata + 3,
                   testdata + 5);
  uint8_t check[] = {0, 0, 8, 7, 9, 8, 7, 6, 5};
  uint8_t check_bad[] = {0, 1, 8, 7, 9, 8, 7, 6, 5};
  const sm_buffer cbuf = sm_buffer_alias(check, sizeof(check));
  const sm_buffer cbuf_bad = sm_buffer_alias(check_bad, sizeof(check));
  SM_ASSERT(sm_buffer_equal(test_buf, cbuf));
  SM_ASSERT(!sm_buffer_equal(test_buf, cbuf_bad));

  // Check sm_buffer_at
  for (size_t i = 0; i < sizeof(check); ++i) {
    SM_ASSERT(sm_buffer_at(test_buf, i) == check[i]);
  }

  // Check sm_buffer_pop
  for (int i = sizeof(check) - 1; i >= 0; --i) {
    SM_ASSERT(sm_buffer_pop(&test_buf) == check[i]);
  }
}
