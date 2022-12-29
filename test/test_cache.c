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

#include "smithy/cache/cache.h"
#include "smithy/stdlib/buffer.h"

int main(int argc, char *argv[]) {
  sm_cache table;
  sm_cache_init(&table, "/private/tmp/smithy_cache_test");

  SM_AUTO(sm_buffer) test_buf = sm_empty_buffer;
  SM_ASSERT(sm_buffer_empty(test_buf));
  sm_buffer_resize(&test_buf, 100);
  SM_ASSERT(sm_buffer_length(test_buf) == 100);
  // Fill the last 99 elements with random numbers
  arc4random_buf(sm_buffer_begin(test_buf) + 1, 99);

  SM_AUTO(sm_buffer) check_buf = sm_empty_buffer;
  sm_buffer_insert(&check_buf, sm_buffer_end(check_buf),
                   sm_buffer_begin(test_buf), sm_buffer_end(test_buf));

  sm_cache_put(&table, "testdata", test_buf);

  sm_buffer_clear(&test_buf);

  sm_cache_get(&table, "testdata", &test_buf);
  SM_ASSERT(sm_buffer_length(test_buf) == 100);
  SM_ASSERT(sm_buffer_equal(test_buf, check_buf));

  sm_cache_cleanup(&table);
}
