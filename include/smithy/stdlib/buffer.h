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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "smithy/stdlib/alloc.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/auto_destruct.h"

typedef struct {
  uint8_t *data;
  size_t length;
  size_t capacity;
} sm_buffer;

#define sm_empty_buffer                                                        \
  (sm_buffer) { .length = 0, .capacity = 0, .data = NULL }

/// NOTE: do not use buffer_auto_t with sm_buffer_alias unless you want the data
/// being aliased to be freed.
#define sm_buffer_alias(arr, len)                                              \
  (sm_buffer) { .length = (len), .capacity = (SIZE_MAX), .data = (arr) }

/// Use this for files that you've mapped into a buffer. This will prevent the
/// buffer from resizing automatically. You take responsibility for ensuring
/// that the buffer does not *need* resizing.
#define sm_buffer_alias_mmap(arr, len)                                         \
  (sm_buffer) { .length = (len), .capacity = (SIZE_MAX), .data = (arr) }

#define sm_buffer_alias_str(str)                                               \
  sm_buffer_alias((uint8_t *)(str), strlen((str)))

/// Check if the buffer is an alias of something else (i.e. not owned).
static inline bool sm_buffer_is_alias(const sm_buffer buf) {
  return buf.capacity == SIZE_MAX;
}

/// Cleanup the buffer. WARNING: Unconditional free, even if it's an alias
/// buffer!
static inline void sm_buffer_cleanup(const sm_buffer buf) { sm_free(buf.data); }

/// Needed for SM_AUTO macro
static inline void free_sm_buffer(const sm_buffer *buf) {
  if (buf) {
    sm_buffer_cleanup(*buf);
  }
}

/// Begin/end iterators
static inline uint8_t *sm_buffer_begin(const sm_buffer buf) { return buf.data; }

static inline uint8_t *sm_buffer_end(const sm_buffer buf) {
  return sm_buffer_begin(buf) + buf.length;
}

/// View a buffer as a string.
static inline char *sm_buffer_as_str(const sm_buffer buf) {
  return (char *)sm_buffer_begin(buf);
}

/// Empty/length
static inline bool sm_buffer_empty(const sm_buffer buf) {
  return sm_buffer_begin(buf) == sm_buffer_end(buf);
}
static inline size_t sm_buffer_length(const sm_buffer buf) {
  return buf.length;
}

/// Single element access
static inline uint8_t sm_buffer_at(const sm_buffer buf, size_t idx) {
  SM_ASSERT(idx < buf.length);
  return sm_buffer_begin(buf)[idx];
}
static inline uint8_t sm_buffer_front(const sm_buffer buf) {
  return sm_buffer_at(buf, 0);
}
static inline uint8_t sm_buffer_back(const sm_buffer buf) {
  return sm_buffer_at(buf, buf.length - 1);
}
static inline void sm_buffer_set(sm_buffer *buf, size_t idx, uint8_t newelt) {
  SM_ASSERT(idx < buf->length);
  *(sm_buffer_begin(*buf) + idx) = newelt;
}

/// Push/pop a single element to/from the end of the buffer.
void sm_buffer_push(sm_buffer *buf, uint8_t elt);
uint8_t sm_buffer_pop(sm_buffer *buf);

/// Inserts data from the range [@first, @last) into @buf ending at @pos.
/// If the buffer is empty (length, capacity == 0, data = NULL) then pos may be
/// NULL, in which case the buffer will be allocated to hold all the data. If
/// the buffer is empty, @pos must be NULL. Mimics std::vector::insert.
void sm_buffer_insert(sm_buffer *buf, uint8_t *pos, const uint8_t *first,
                      const uint8_t *last);
/// Fills the buffer with CSPRNG-generated random data between first and last.
/// Similar to std::fill. @last may be NULL, in which case it defaults to
/// sm_buffer_end(buf)
void sm_buffer_fill_rand(sm_buffer buf, uint8_t *pos, const uint8_t *last);
/// Grows the buffer if newsize is larger than the current capacity, and sets
/// buf->length = newsize
void sm_buffer_resize(sm_buffer *buf, size_t newlen);
/// Grows the buffer if newcap is larger than the current capacity. Does NOT
/// reset buf->length.
void sm_buffer_reserve(sm_buffer *buf, size_t newcap);
/// Sets the buffer contents to 0 and sets buf->length = 0. After this call,
/// sm_buffer_empty(buf) == true.
void sm_buffer_clear(sm_buffer *buf);
/// Constant-time memcmp for 2 buffers
bool sm_buffer_equal(sm_buffer lhs, sm_buffer rhs);
/// Return an iterator into a buffer if the element is found.
uint8_t *sm_buffer_find(sm_buffer buf, uint8_t to_find);
/// Return true if the prefix matches.
bool sm_buffer_has_prefix(sm_buffer buf, sm_buffer prefix);
/// Return true if the suffix matches.
bool sm_buffer_has_suffix(sm_buffer buf, sm_buffer prefix);
/// Print a string into a buffer
void sm_buffer_print(sm_buffer *buf, const char *fmt, ...);
void sm_buffer_vprint(sm_buffer *buf, const char *fmt, va_list args);

/// Clone a buffer - this means allocating a new buffer and copying `buf` into
/// it.
static inline sm_buffer sm_buffer_clone(const sm_buffer buf) {
  sm_buffer out = sm_empty_buffer;
  sm_buffer_insert(&out, sm_buffer_begin(out), sm_buffer_begin(buf),
                   sm_buffer_end(buf));
  return out;
}

/// Copy the contents of `buf` into `out`.
static inline void sm_buffer_copy(const sm_buffer buf, sm_buffer *out) {
  sm_buffer_insert(out, sm_buffer_begin(*out), sm_buffer_begin(buf),
                   sm_buffer_end(buf));
}
