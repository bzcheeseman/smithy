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

typedef struct {
  size_t element_size;
  size_t wr;
  size_t rd;
  sm_buffer buf;
} sm_circular_buffer;

// All of these functions are provided in the header file because they're very
// small and should be inlined when possible.

/// Initialize a circular buffer with a given number of elements and a given
/// element size.
static inline void sm_circular_buffer_init(sm_circular_buffer *c,
                                           size_t num_elts,
                                           size_t element_size) {
  c->element_size = element_size;
  c->wr = 0;
  c->rd = 0;
  c->buf = sm_empty_buffer;
  sm_buffer_reserve(&c->buf, num_elts * element_size);
}

#define sm_circular_buffer_alias(esize, buffer)                                \
  (sm_circular_buffer) {                                                       \
    .element_size = (esize), .wr = 0, .rd = 0, .buf = (buffer)                 \
  }

/// Cleanup the circular buffer.
static inline void sm_circular_buffer_cleanup(const sm_circular_buffer *c) {
  if (c) {
    sm_buffer_cleanup(c->buf);
  }
}

/// Check if the buffer is full.
static inline bool sm_circular_buffer_full(const sm_circular_buffer c) {
  return c.buf.length == c.buf.capacity;
}

/// Check if the buffer is empty.
static inline bool sm_circular_buffer_empty(const sm_circular_buffer c) {
  return c.buf.length == 0;
}

/// Get a pointer to the current write slot.
static inline uint8_t *
sm_circular_buffer_write_slot(const sm_circular_buffer c) {
  return sm_buffer_begin(c.buf) + c.wr;
}

/// Increment the current write slot.
static inline void sm_circular_buffer_incr_write_slot(sm_circular_buffer *c) {
  c->wr = (c->wr + c->element_size) % c->buf.capacity;
  // Use the buffer's length to track the number of elements in the queue. Since
  // the queue is a fixed size, only increase the length if it isn't already at
  // the maximum.
  if (c->buf.length != c->buf.capacity) {
    c->buf.length += c->element_size;
  }
}

/// Get a pointer to the current read slot.
static inline uint8_t *
sm_circular_buffer_read_slot(const sm_circular_buffer c) {
  return sm_buffer_begin(c.buf) + c.rd;
}

/// Increment the current read slot.
static inline void sm_circular_buffer_incr_read_slot(sm_circular_buffer *c) {
  c->rd = (c->rd + c->element_size) % c->buf.capacity;
  // Use the buffer's length to track the number of elements in the queue
  c->buf.length -= c->element_size;
}
