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

void *sm_malloc(size_t size);
void *sm_calloc(size_t count, size_t size);
void *sm_realloc(void *p, size_t newsz);
void *sm_safe_realloc(void *p, size_t newsz);
void sm_free(void *p);
char *sm_strdup(const char *s);

#define sm_safe_realloc_array(ptr, newlen)                                     \
  sm_safe_realloc((ptr), (newlen) * sizeof(*(ptr)))
