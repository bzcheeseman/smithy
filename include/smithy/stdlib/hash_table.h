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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/buffer.h"

typedef struct {
  size_t capacity;
  sm_buffer *keys;
  sm_buffer *data;
} sm_hash_table;

void sm_hash_table_init(sm_hash_table *t);
void sm_hash_table_cleanup(sm_hash_table *t);

/// Needed for SM_AUTO macro
static inline void free_sm_hash_table(sm_hash_table *t) {
  sm_hash_table_cleanup(t);
}

// Overwrites any data in the map with key @key
void sm_hash_table_put(sm_hash_table *t, const sm_buffer key, const sm_buffer data);
// Appends @data to any buffers in the map keyed to @key
void sm_hash_table_append(sm_hash_table *t, const sm_buffer key, const sm_buffer data);
// Gets the data at @key and places it at the end of @out. Returns true if the
// item existed
bool sm_hash_table_get(sm_hash_table *t, const sm_buffer key, sm_buffer *out);
// Get the item but do not copy the data.
bool sm_hash_table_get_alias(sm_hash_table *t, const sm_buffer key, sm_buffer *out);
// Checks if a given key exists
bool sm_hash_table_exists(sm_hash_table *t, const sm_buffer key);
// Remove an item from the hash table by clearing out the buffer and freeing the
// key.
void sm_hash_table_remove(sm_hash_table *t, const sm_buffer key);

void sm_hash_table_clear(sm_hash_table *t);
