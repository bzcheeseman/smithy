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

#include "smithy/stdlib/queue.h"

static const size_t nelts = 1000000;

void simple(const sm_queue **q) {
  bool growable = sm_queue_can_grow(q);
  for (int i = 0; i < nelts; ++i) {
    size_t elt = i;
    SM_ASSERT((*q)->push(q, &elt));
  }

  if (!growable) {
    size_t shouldfail = 0;
    SM_ASSERT(!(*q)->push(q, &shouldfail));
  }

  size_t elt;
  for (int i = 0; i < nelts; ++i) {
    SM_ASSERT((*q)->pop(q, (void *)&elt));
    SM_ASSERT(elt == i);
  }
  SM_ASSERT(!(*q)->pop(q, (void *)&elt) || growable);
}

struct c {
  char *string;
  int i;
};
const char teststr[] = "Hello there!";

// This makes sure that if you pack data immediately after the object it will
// also be copied
void complex(const sm_queue **q) {
  bool growable = sm_queue_can_grow(q);
  sm_buffer teststr_buf = sm_buffer_alias_str(teststr);

  struct c *elt = sm_malloc(sizeof(struct c) + sizeof(teststr));
  elt->string = ((char *)elt + sizeof(struct c));
  memcpy(elt->string, teststr, sizeof(teststr));
  for (int i = 0; i < nelts; ++i) {
    elt->i = i;
    SM_ASSERT((*q)->push(q, elt));
  }
  sm_free(elt);
  if (!growable) {
    uint8_t *shouldfail = 0;
    SM_ASSERT(!(*q)->push(q, &shouldfail));
  }

  struct c *out = sm_malloc(sizeof(struct c) + sizeof(teststr));
  for (int i = 0; i < nelts; ++i) {
    SM_ASSERT((*q)->pop(q, (void *)out));
    // This is needed to unpack the string correctly
    out->string = (char *)out + sizeof(struct c);

    sm_buffer elt_alias = sm_buffer_alias_str(out->string);
    SM_ASSERT(sm_buffer_equal(elt_alias, teststr_buf));
    SM_ASSERT(out->i == i);
  }
  SM_ASSERT(!(*q)->pop(q, (void *)out));
  sm_free(out);
}

int main() {
  SM_INFO("Starting fixed-size queue test...");
  { // Test fixed-size queue
    SM_AUTO(sm_fixed_size_queue) simple_fs;
    sm_fixed_size_queue_init(&simple_fs, nelts, sizeof(size_t));
    simple((const sm_queue **)&simple_fs);

    SM_AUTO(sm_fixed_size_queue) complex_fs;
    sm_fixed_size_queue_init(&complex_fs, nelts,
                             sizeof(struct c) + sizeof(teststr));
    complex((const sm_queue **)&complex_fs);
  }
  SM_INFO("Done\n");

  SM_INFO("Starting growable queue test...");
  {
    SM_AUTO(sm_growable_queue) simple_g;
    sm_growable_queue_init(&simple_g, sizeof(size_t));
    simple((const sm_queue **)&simple_g);

    SM_AUTO(sm_growable_queue) complex_g;
    sm_growable_queue_init(&complex_g, sizeof(struct c) + sizeof(teststr));
    complex((const sm_queue **)&complex_g);
  }
  SM_INFO("Done\n");
}
