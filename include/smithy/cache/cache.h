//
// Copyright 2022 Aman LaChapelle
// Full license at keyderiver/LICENSE.txt
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

#include "smithy/stdlib/hash_table.h"

// Implements a write-through cache that may or may not have a filesystem
// backing
typedef struct {
  sm_hash_table hot;
  char *path;
} sm_cache;

void sm_cache_init(sm_cache *c);
void sm_cache_cleanup(sm_cache *c);

void sm_cache_set_dir(sm_cache *c, const char *path);
void sm_cache_set_nodir(sm_cache *c);

void sm_cache_put(sm_cache *c, const char *key, const sm_buffer data);
bool sm_cache_get(sm_cache *c, const char *key, sm_buffer *out);
// Checks if a given key exists
bool sm_cache_exists(sm_cache *c, const char *key);
void sm_cache_remove(sm_cache *c, const char *key);
void sm_cache_clear(sm_cache *c);
