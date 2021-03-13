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

#include "smithy/stdlib/circular_buffer.h"
#include "smithy/stdlib/linked_list.h"

typedef struct sm_queue_ sm_queue;
struct sm_queue_ {
  size_t context_size;
  // Will not overwrite the oldest element. Returns true if insertion succeeded.
  // Element may be NULL, to check if the queue is writeable or not. No push
  // actually happens if element is NULL.
  bool (*push)(const sm_queue **q, void *element);
  // May overwrite the oldest element in the queue. element must not be NULL.
  void (*force_push)(const sm_queue **q, void *element);
  // Returns true if an element was returned. If the queue is empty, this cannot
  // return true.
  bool (*pop)(const sm_queue **q, void *element);
  // Get the element size
  size_t (*element_size)(const sm_queue **q);
  // Cleans up resources associated with the queue
  void (*cleanup)(const sm_queue **q);
  // Checks if the queue has anything in it.
  bool (*empty)(const sm_queue **q);
};

// Implements a queue within a circular buffer
extern const sm_queue sm_fixed_size_queue_vtable;
typedef struct {
  const sm_queue *vtable;
  sm_circular_buffer buf;
} sm_fixed_size_queue;

// Copies element_size bytes per push/pop. See test/test_queue.c:complex() for
// an example of packing data after the struct
void sm_fixed_size_queue_init(sm_fixed_size_queue *q, size_t qlen,
                              size_t element_size);
static inline void free_sm_fixed_size_queue(sm_fixed_size_queue *q) {
  if (q) {
    q->vtable->cleanup(&q->vtable);
  }
}

typedef struct {
  sm_ilist list;
  void *data;
} sm_growable_queue_node;

extern const sm_queue sm_growable_queue_vtable;
typedef struct {
  const sm_queue *vtable;
  sm_growable_queue_node *head;
  sm_growable_queue_node *tail;
  size_t element_size;
} sm_growable_queue;

void sm_growable_queue_init(sm_growable_queue *q, size_t element_size);
static inline void free_sm_growable_queue(sm_growable_queue *q) {
  if (q) {
    q->vtable->cleanup(&q->vtable);
  }
}

static inline bool sm_queue_can_grow(const sm_queue **q) {
  return (*q) == &sm_growable_queue_vtable;
}
