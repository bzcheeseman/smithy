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
#include "smithy/stdlib/hash_table.h"

int main() {
  SM_AUTO(sm_hash_table) table;
  sm_hash_table_init(&table);

  SM_ASSERT(!sm_hash_table_exists(&table, sm_buffer_alias_str("testdata")));

  SM_AUTO(sm_buffer) test_buf = sm_empty_buffer;
  SM_ASSERT(sm_buffer_empty(test_buf));
  sm_buffer_resize(&test_buf, 100);
  SM_ASSERT(sm_buffer_length(test_buf) == 100);
  // Fill the last 99 elements with random numbers
  arc4random_buf(sm_buffer_begin(test_buf) + 1, 99);

  SM_AUTO(sm_buffer) check_buf = sm_empty_buffer;
  sm_buffer_insert(&check_buf, sm_buffer_end(check_buf),
                   sm_buffer_begin(test_buf), sm_buffer_end(test_buf));

  sm_hash_table_put(&table, sm_buffer_alias_str("testdata"), test_buf);

  sm_buffer_clear(&test_buf);

  sm_hash_table_get(&table, sm_buffer_alias_str("testdata"), &test_buf);
  SM_ASSERT(sm_buffer_length(test_buf) == 100);
  SM_ASSERT(sm_buffer_equal(test_buf, check_buf));

  SM_AUTO(sm_buffer) new_test = sm_empty_buffer;
  sm_buffer_resize(&new_test, 20);
  SM_ASSERT(sm_buffer_length(new_test) == 20);
  // Fill with random numbers
  arc4random_buf(sm_buffer_begin(new_test), 20);
  sm_buffer_insert(&check_buf, sm_buffer_end(check_buf),
                   sm_buffer_begin(new_test), sm_buffer_end(new_test));

  // Test that append works
  sm_hash_table_append(&table, sm_buffer_alias_str("testdata"), new_test);

  sm_buffer_clear(&test_buf);

  sm_hash_table_get(&table, sm_buffer_alias_str("testdata"), &test_buf);
  SM_ASSERT(sm_buffer_length(test_buf) == 120);
  SM_ASSERT(sm_buffer_equal(test_buf, check_buf));

  // Test that we can retrieve after a resize operation
  for (size_t i = 0; i < 8; ++i) {
    sm_hash_table_put(&table, sm_buffer_alias(&i, sizeof(size_t)),
                      sm_buffer_alias(&i, sizeof(size_t)));
  }

  sm_buffer_clear(&test_buf);
  sm_hash_table_get(&table, sm_buffer_alias_str("testdata"), &test_buf);
  SM_ASSERT(sm_buffer_length(test_buf) == 120);
  SM_ASSERT(sm_buffer_equal(test_buf, check_buf));

  sm_buffer out;
  for (size_t i = 0; i < 8; ++i) {
    sm_hash_table_get_alias(&table, sm_buffer_alias(&i, sizeof(size_t)), &out);
    SM_ASSERT(sm_buffer_equal(out, sm_buffer_alias(&i, sizeof(size_t))));
  }
}
