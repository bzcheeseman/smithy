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

#include "smithy/stdlib/buffer.h"

/// Provides helpers to alias a sm_buffer to a typed vector.

#define sm_typed_vector_alias(arr, len)                                        \
  sm_buffer_alias((uint8_t *)(arr), (len) * sizeof(*(arr)))

#define sm_typed_vector_insert(buf, pos, obj)                                  \
  sm_buffer_insert((buf), (pos), (uint8_t *)(obj),                             \
                   ((uint8_t *)(obj) + sizeof(*(obj))))

#define sm_typed_vector_push(buf, obj)                                         \
  sm_typed_vector_insert((buf), sm_buffer_end(*(buf)), &(obj))

#define sm_typed_vector_length(T, buf) sm_buffer_length((buf)) / sizeof(T)

#define sm_typed_vector_gep(T, buf, idx)                                       \
  (T *)(sm_buffer_begin((buf)) + ((idx) * sizeof(T)))
#define sm_typed_vector_at(T, buf, idx) *sm_typed_vector_gep(T, buf, idx)

#define sm_typed_vector_resize(T, buf, newlen)                                 \
  sm_buffer_resize(buf, sizeof(T) * (newlen))
