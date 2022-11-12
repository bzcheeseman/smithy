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

#include <stdatomic.h>

// TODO: make this resize-able with a semaphore

/// This is essentially the same as sm_circular_buffer but with a thread-safe
/// construction.

typedef struct {
  /// The size of a single element in the queue. This is constant for the
  /// lifetime of the queue.
  size_t element_size;
  /// The size of the queue in number of elements. This is not necessarily
  /// constant for the lifetime of the queue!
  atomic_size_t qsize;
  /// The write head as a byte index.
  atomic_size_t wr;
  /// The read head as a byte index.
  atomic_size_t rd;
  /// The underlying queue storage.
  uint8_t *buf;
} sm_concurrent_queue;

// All of these functions are provided in the header file because they're very
// small and should be inlined when possible.

/// Initialize a concurrent queue to empty. This provides a single queue size,
/// the total number of bytes allocated is `qsize * element_size`.
static inline void sm_concurrent_queue_init(sm_concurrent_queue *c,
                                            size_t qsize, size_t element_size) {
  c->element_size = element_size;
  atomic_init(&c->qsize, qsize);
  atomic_init(&c->wr, 0);
  atomic_init(&c->rd, 0);
  c->buf = calloc(qsize * element_size, 1);
}

static inline void free_sm_concurrent_queue(sm_concurrent_queue *c) {
  if (c)
    free(c->buf);
}

static inline bool sm_concurrent_queue_empty(const sm_concurrent_queue *c) {
  return atomic_load(&c->wr) == atomic_load(&c->rd);
}

static inline uint8_t *
sm_concurrent_queue_write_slot(const sm_concurrent_queue *c) {
  return c->buf +
         atomic_load(&c->wr) % (c->element_size * atomic_load(&c->qsize));
}

static inline void sm_concurrent_queue_incr_write_slot(sm_concurrent_queue *c) {
  atomic_fetch_add(&c->wr, c->element_size);
}

static inline uint8_t *
sm_concurrent_queue_read_slot(const sm_concurrent_queue *c) {
  return c->buf +
         atomic_load(&c->rd) % (c->element_size * atomic_load(&c->qsize));
}

static inline void sm_concurrent_queue_incr_read_slot(sm_concurrent_queue *c) {
  atomic_fetch_add(&c->rd, c->element_size);
}

/// The queue is full if the write slot and the read slot are equal, but it's
/// not empty.
static inline bool sm_concurrent_queue_full(const sm_concurrent_queue *c) {
  return sm_concurrent_queue_read_slot(c) ==
             sm_concurrent_queue_write_slot(c) &&
         !sm_concurrent_queue_empty(c);
}

/// Pop can fail if the queue is empty. Returns NULL on failure, the pointer to
/// the head of the element on success.
static inline uint8_t *sm_concurrent_queue_pop(sm_concurrent_queue *c) {
  if (sm_concurrent_queue_empty(c))
    return NULL;

  uint8_t *slot = sm_concurrent_queue_read_slot(c);
  sm_concurrent_queue_incr_read_slot(c);
  return slot;
}

/// Push can fail if the queue is full. Returns false on failure, true on
/// success.
static inline bool sm_concurrent_queue_push(sm_concurrent_queue *c,
                                            uint8_t *ptr) {
  if (sm_concurrent_queue_full(c))
    return false;

  memcpy(sm_concurrent_queue_write_slot(c), ptr, c->element_size);
  sm_concurrent_queue_incr_write_slot(c);
  return true;
}
