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

#include "smithy/stdlib/queue.h"

//=====--- Fixed-size queue using sm_circular_buffer ---=====//

void sm_fixed_size_queue_init(sm_fixed_size_queue *q, size_t qsize,
                              size_t element_size) {
  q->vtable = &sm_fixed_size_queue_vtable;
  sm_circular_buffer_init(&q->buf, qsize, element_size);
}

static void fs_queue_force_push(sm_fixed_size_queue *q, void *element) {
  if (element == NULL) {
    return;
  }

  uint8_t *slot = sm_circular_buffer_write_slot(q->buf);
  memcpy(slot, element, q->buf.element_size);
  sm_circular_buffer_incr_write_slot(&q->buf);
}

static bool fs_queue_push(sm_fixed_size_queue *q, void *element) {
  // If the buffer length is the same as its capacity, then the queue is full
  if (sm_circular_buffer_full(q->buf)) {
    return false;
  }

  // If the element is NULL, then a push *would* succeed so return true but
  // don't push (pushing NULL will result in undefined behavior)
  if (element == NULL) {
    return true;
  }

  fs_queue_force_push(q, element);
  return true;
}

static bool fs_queue_pop(sm_fixed_size_queue *q, void *element) {
  SM_ASSERT(element != NULL);
  if (sm_circular_buffer_empty(q->buf)) {
    return false;
  }

  uint8_t *slot = sm_circular_buffer_read_slot(q->buf);
  memcpy(element, slot, q->buf.element_size);
  sm_circular_buffer_incr_read_slot(&q->buf);
  return true;
}

static size_t fs_queue_element_size(sm_fixed_size_queue *q) {
  return q->buf.element_size;
}

static void fs_queue_cleanup(sm_fixed_size_queue *q) {
  free_sm_circular_buffer(&q->buf);
}

static bool fs_queue_empty(sm_fixed_size_queue *q) {
  return sm_circular_buffer_empty(q->buf);
}

const sm_queue sm_fixed_size_queue_vtable = {
    .context_size = sizeof(sm_fixed_size_queue),
    .push = (bool (*)(const sm_queue **, void *))(&fs_queue_push),
    .force_push = (void (*)(const sm_queue **, void *))(&fs_queue_force_push),
    .pop = (bool (*)(const sm_queue **, void *))(&fs_queue_pop),
    .element_size = (size_t(*)(const sm_queue **))(&fs_queue_element_size),
    .cleanup = (void (*)(const sm_queue **))(&fs_queue_cleanup),
    .empty = (bool (*)(const sm_queue **))(&fs_queue_empty),
};

//=====--- Growable queue using sm_ilist ---=====//

void sm_growable_queue_init(sm_growable_queue *q, size_t element_size) {
  q->vtable = &sm_growable_queue_vtable;
  q->head = NULL;
  q->element_size = element_size;
}

static bool g_queue_push(sm_growable_queue *q, void *element) {
  sm_growable_queue_node *new_node =
      sm_malloc(sizeof(sm_growable_queue_node) + q->element_size);
  // Point the data buffer to just after the node itself
  new_node->data = (uint8_t *)new_node + sizeof(sm_growable_queue_node);
  // And copy the data in
  memcpy(new_node->data, element, q->element_size);
  if (q->head == NULL) {
    q->head = new_node;
    q->tail = q->head;
  } else {
    sm_ilist_push_back((sm_ilist *)q->tail, (sm_ilist *)new_node);
    q->tail = new_node;
  }

  return true;
}

static void g_queue_force_push(sm_growable_queue *q, void *element) {
  g_queue_push(q, element);
}

static bool g_queue_pop(sm_growable_queue *q, void *element) {
  SM_ASSERT(element != NULL);
  if (q->head == NULL) {
    return false;
  }

  // Copy the data out
  memcpy(element, q->head->data, q->element_size);
  // And clean up that node
  sm_growable_queue_node *curr_head = q->head;
  q->head = (sm_growable_queue_node *)sm_ilist_next((sm_ilist *)q->head);
  sm_free(curr_head);
  return true;
}

static size_t g_queue_element_size(sm_growable_queue *q) {
  return q->element_size;
}

static void g_queue_cleanup(sm_growable_queue *q) {
  sm_growable_queue_node *iter;
  sm_ilist_for_each(q->head, iter) {
    // Just free the iterator
    sm_free(iter);
  }
}

static bool g_queue_empty(sm_growable_queue *q) { return q->head == NULL; }

const sm_queue sm_growable_queue_vtable = {
    .context_size = sizeof(sm_growable_queue),
    .push = (bool (*)(const sm_queue **, void *))(&g_queue_push),
    .force_push = (void (*)(const sm_queue **, void *))(&g_queue_force_push),
    .pop = (bool (*)(const sm_queue **, void *))(&g_queue_pop),
    .element_size = (size_t(*)(const sm_queue **))(&g_queue_element_size),
    .cleanup = (void (*)(const sm_queue **))(&g_queue_cleanup),
    .empty = (bool (*)(const sm_queue **))(&g_queue_empty),
};
