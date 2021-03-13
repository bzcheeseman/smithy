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

#include "smithy/stdlib/hash_table.h"
#include "smithy/stdlib/alloc.h"

#ifndef SM_HASH_TABLE_INIT_CAPACITY
#define SM_HASH_TABLE_INIT_CAPACITY 8
#endif

void sm_hash_table_init(sm_hash_table *t) {
  t->capacity = 0;
  t->data = NULL;
  t->keys = NULL;
}

void sm_hash_table_cleanup(sm_hash_table *t) {
  sm_hash_table_clear(t);
  sm_free(t->keys);
  sm_free(t->data);
}

// Hash from DJB - TODO: replace with SipHash-2-4-64 (or 1-2-64?)
static size_t hash_key(const sm_buffer key) {
  size_t hash = 5381;
  for (const uint8_t *k = sm_buffer_begin(key), *end = sm_buffer_end(key);
       k != end; ++k) {
    hash = ((hash << 5) + hash) + (uint8_t)*k;
  }
  return hash;
}

// Doubles the size of elements in the hash table
static void grow_hash_table(sm_hash_table *t) {
  size_t newcap = t->capacity * 2;
  if (newcap == 0) {
    newcap = SM_HASH_TABLE_INIT_CAPACITY;
  }

  t->keys = sm_realloc(t->keys, newcap * sizeof(sm_buffer));
  // Clean out the newly allocated keys
  volatile sm_buffer *k = (volatile sm_buffer *)(t->keys + t->capacity);
  for (size_t i = 0; i < (newcap - t->capacity); ++i) {
    *k = sm_empty_buffer;
    ++k;
  }

  t->data = sm_realloc(t->data, newcap * sizeof(sm_buffer));
  // Clean out the newly allocated buffers
  volatile sm_buffer *buf = t->data + t->capacity;
  for (size_t i = 0; i < (newcap - t->capacity); ++i) {
    *buf = sm_empty_buffer;
    ++buf;
  }

  // Set the capacity
  t->capacity = newcap;

  for (size_t i = 0; i < t->capacity; ++i) {
    if (sm_buffer_empty(t->keys[i])) {
      continue;
    }

    // Save the key and value (don't want to dealloc them though)
    sm_buffer key = t->keys[i];
    sm_buffer data = t->data[i];

    // Remove it from the table (rather, mark it as ok to overwrite)
    t->keys[i].length = 0;
    t->data[i].length = 0;

    // And re-insert
    sm_hash_table_put(t, key, data);
  }
}

static size_t hash_table_insert(sm_hash_table *t, const sm_buffer key) {
  if (t->capacity == 0) {
    grow_hash_table(t);
  }

  size_t idx = hash_key(key) % t->capacity;
  while (!sm_buffer_empty(t->keys[idx]) &&
         !sm_buffer_equal(key, t->keys[idx])) {
    // TODO: robin hood hashing
    if (idx + 1 == t->capacity) {
      grow_hash_table(t);
      return hash_table_insert(t, key);
    }

    ++idx;
  }

  return idx;
}

static size_t hash_table_find(sm_hash_table *t, const sm_buffer key) {
  // If it's empty then definitely hasn't been found.
  if (t->capacity == 0) {
    return SIZE_MAX;
  }

  size_t idx = hash_key(key) % t->capacity;

  // Make sure it exists first
  if (sm_buffer_empty(t->keys[idx])) {
    return SIZE_MAX;
  }

  // Linearly-probed hash table
  while (!sm_buffer_equal(t->keys[idx], key)) {
    if (idx + 1 == t->capacity) {
      return SIZE_MAX;
    }

    ++idx;
  }

  // The keys match, return the index
  return idx;
}

void sm_hash_table_put(sm_hash_table *t, const sm_buffer key,
                       const sm_buffer data) {
  size_t idx = hash_table_insert(t, key);
  SM_ASSERT(idx != SIZE_MAX);

  // This should be empty, but it's fine either way. We just add it to the end
  // if there is already data in that bucket.
  sm_buffer *tgt = &t->data[idx];

  // Do the insert at the beginning so as to overwrite data in the map
  sm_buffer_insert(tgt, sm_buffer_begin(*tgt), sm_buffer_begin(data),
                   sm_buffer_end(data));

  // Done, copy in the key but only if needed
  if (!sm_buffer_empty(t->keys[idx]) &&
      sm_buffer_length(t->keys[idx]) == sm_buffer_length(key) &&
      sm_buffer_equal(t->keys[idx], key)) {
    // It's the same key, so we just appended to the same buffer.
    return;
  }

  sm_buffer_clear(&t->keys[idx]);
  sm_buffer_insert(&t->keys[idx], sm_buffer_begin(t->keys[idx]),
                   sm_buffer_begin(key), sm_buffer_end(key));
}

void sm_hash_table_append(sm_hash_table *t, const sm_buffer key,
                          const sm_buffer data) {
  size_t idx = hash_table_insert(t, key);
  SM_ASSERT(idx != SIZE_MAX);

  // This should be empty, but it's fine either way. We just add it to the end
  // if there is already data in that bucket.
  sm_buffer *tgt = &t->data[idx];

  // Do the insert
  sm_buffer_insert(tgt, sm_buffer_end(*tgt), sm_buffer_begin(data),
                   sm_buffer_end(data));

  // Done, copy in the key but only if needed
  if (!sm_buffer_empty(t->keys[idx]) &&
      sm_buffer_length(t->keys[idx]) == sm_buffer_length(key) &&
      sm_buffer_equal(t->keys[idx], key)) {
    // It's the same key, so we just appended to the same buffer.
    return;
  }

  sm_buffer_clear(&t->keys[idx]);
  sm_buffer_insert(&t->keys[idx], sm_buffer_begin(t->keys[idx]),
                   sm_buffer_begin(key), sm_buffer_end(key));
}

bool sm_hash_table_get(sm_hash_table *t, const sm_buffer key, sm_buffer *out) {
  size_t idx = hash_table_find(t, key);
  if (idx == SIZE_MAX) {
    return false;
  }

  sm_buffer tgt = t->data[idx];

  // The output buffer should be empty but it's fine either way.

  // Do the insert into the end of the output buffer
  sm_buffer_insert(out, sm_buffer_end(*out), sm_buffer_begin(tgt),
                   sm_buffer_end(tgt));

  // Done
  return true;
}

bool sm_hash_table_get_alias(sm_hash_table *t, const sm_buffer key,
                             sm_buffer *out) {
  size_t idx = hash_table_find(t, key);
  if (idx == SIZE_MAX) {
    return false;
  }

  sm_buffer tgt = t->data[idx];

  // Just alias the data in the target buffer
  *out = sm_buffer_alias(tgt.data, tgt.length);

  // Done
  return true;
}

bool sm_hash_table_exists(sm_hash_table *t, const sm_buffer key) {
  size_t idx = hash_table_find(t, key);
  return idx != SIZE_MAX;
}

void sm_hash_table_remove(sm_hash_table *t, const sm_buffer key) {
  size_t idx = hash_table_find(t, key);
  if (idx == SIZE_MAX) {
    return; // doesn't exist
  }

  // Clear out the data
  sm_buffer *tgt = &t->data[idx];
  sm_buffer_clear(tgt);

  // Clear out the key
  sm_buffer_clear(&t->keys[idx]);
}

void sm_hash_table_clear(sm_hash_table *t) {
  for (size_t i = 0; i < t->capacity; ++i) {
    sm_buffer_clear(&t->keys[i]);
    free_sm_buffer(&t->keys[i]);
    sm_buffer_clear(&t->data[i]);
    free_sm_buffer(&t->data[i]);
  }
}
