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

/// This queue state holds the read and write pointers together in a single
/// struct in order to ensure that they are synchronized together, especially
/// when pushing/popping from the queue.
typedef struct {
  /// Read pointer as an element index.
  uint32_t read;
  /// Write pointer as an element index.
  uint32_t write;
} queue_state;

_Static_assert(sizeof(queue_state) == sizeof(uint64_t),
               "queue state must be 64 bits exactly");

typedef struct {
  /// The size of a single element in the queue. This is constant for the
  /// lifetime of the queue.
  size_t element_size;
  /// The size of the queue in number of elements. This is not necessarily
  /// constant for the lifetime of the queue!
  atomic_size_t qsize;
  /// The state of the queue (read + write pointers).
  _Atomic(queue_state) state;
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
  queue_state initial_state = {0, 0};
  atomic_init(&c->state, initial_state);
  c->buf = calloc(qsize * element_size, 1);
}

static inline void free_sm_concurrent_queue(sm_concurrent_queue *c) {
  if (c)
    free(c->buf);
}

static inline bool sm_concurrent_queue_empty(const sm_concurrent_queue *c) {
  queue_state curr = atomic_load(&c->state);
  return curr.read == curr.write;
}

static inline uint8_t *
sm_concurrent_queue_write_slot(const sm_concurrent_queue *c) {
  queue_state curr = atomic_load(&c->state);
  return c->buf + (curr.write % atomic_load(&c->qsize)) * c->element_size;
}

static inline void sm_concurrent_queue_incr_write_slot(sm_concurrent_queue *c) {
  // Because the compare_exchange_weak loads the current state into `curr` we
  // can just set it to something and it should work.
  queue_state curr = atomic_load_explicit(&c->state, memory_order_relaxed);
  queue_state next = {curr.read, curr.write + 1};
  while (!atomic_compare_exchange_weak(&c->state, &curr, next)) {
    next.read = curr.read;
    next.write = curr.write + 1;
  }
}

static inline uint8_t *
sm_concurrent_queue_read_slot(const sm_concurrent_queue *c) {
  queue_state curr = atomic_load(&c->state);
  return c->buf + (curr.read % atomic_load(&c->qsize)) * c->element_size;
}

static inline void sm_concurrent_queue_incr_read_slot(sm_concurrent_queue *c) {
  // Because the compare_exchange_weak loads the current state into `curr` we
  // can just set it to something and it should work.
  queue_state curr = atomic_load_explicit(&c->state, memory_order_relaxed);
  queue_state next = {curr.read + 1, curr.write};
  while (!atomic_compare_exchange_weak(&c->state, &curr, next)) {
    next.read = curr.read + 1;
    next.write = curr.write;
  }
}

/// The queue is full if the write slot and the read slot are equal, but it's
/// not empty.
static inline bool sm_concurrent_queue_full(const sm_concurrent_queue *c) {
  return sm_concurrent_queue_read_slot(c) ==
             sm_concurrent_queue_write_slot(c) &&
         !sm_concurrent_queue_empty(c);
}

/// Peek can fail if the queue is empty. Returns NULL on failure, and the
/// pointer to the head of the element on success. Does not increment the read
/// pointer.
static inline uint8_t *sm_concurrent_queue_peek(sm_concurrent_queue *c) {
  if (sm_concurrent_queue_empty(c))
    return NULL;

  uint8_t *slot = sm_concurrent_queue_read_slot(c);
  return slot;
}

/// Pop can fail if the queue is empty. Returns NULL on failure, the pointer to
/// the head of the element on success. Increments the read pointer.
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
