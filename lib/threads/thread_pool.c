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

#include "smithy/threads/thread_pool.h"
#include "smithy/stdlib/memory.h"

#include <errno.h>
#include <unistd.h>

typedef struct {
  sm_concurrent_queue *q;
  atomic_int *pending;
  sm_semaphore *q_ready;
  worker_fn work;
} thread_args;

// Needed for using SM_AUTO here
static void free_void(void **p) {
  if (p)
    sm_free(*p);
}
static void free_uint8_t(uint8_t **p) {
  if (p)
    sm_free(*p);
}

// The stop signal is 0xff for each byte of the message
static bool is_stop_signal(void *e, size_t bytes) {
  uint8_t *sig = e;
  bool is_stop = false;
  if (sig[0] == 0xff) {
    is_stop = true;
    for (size_t i = 1; i < bytes; ++i)
      is_stop &= sig[i] == 0xff;
  }
  return is_stop;
}

static void *thread_func(void *args) {
  thread_args *a = args;
  // Get the element size
  size_t element_size = a->q->element_size;
  // Alloc the element (and since we have SM_AUTO, don't have to worry about
  // free)
  SM_AUTO(void) *element = sm_calloc(1, element_size);

  bool keep_going = true;
  while (keep_going) {
    // Wait for work
    int err = sm_semaphore_wait(a->q_ready);
    if (err != 0)
      SM_FATAL("sm_semaphore_wait failed with %s\n", strerror(errno));

    uint8_t *read = sm_concurrent_queue_peek(a->q);
    if (read) {
      // Copy from the queue to the local element because it may be overwritten.
      memcpy(element, read, element_size);
      // Now it's OK to pop - we can overwrite the data now.
      sm_concurrent_queue_pop(a->q);
      // If it's not the stop signal, then do the work.
      keep_going = !is_stop_signal(element, element_size);
      if (keep_going)
        a->work((void *)read);
    }

    // Subtract 1 from the number of pending jobs - I just did one.
    atomic_fetch_sub_explicit(a->pending, 1, memory_order_relaxed);
  }

  return NULL;
}

// TODO: tune queue depth
void sm_thread_pool_init(sm_thread_pool *pool, size_t work_elt_size,
                         worker_fn worker) {
  sm_concurrent_queue_init(&pool->q, 32, work_elt_size);
  pool->sema = sm_semaphore_open(0);
  if (pool->sema == SEM_FAILED)
    SM_FATAL("Failed to create semaphore with %s\n", strerror(errno));

  // Set the pending jobs to 0.
  atomic_exchange(&pool->pending, 0);

  pool->args = sm_malloc(sizeof(thread_args));
  thread_args *args = pool->args;
  args->q = &pool->q;
  args->pending = &pool->pending;
  args->q_ready = pool->sema;
  args->work = worker;

  for (int i = 0; i < SM_THREAD_POOL_THREADS; ++i)
    pthread_create(&pool->workers[i], NULL, &thread_func, args);
}

void sm_thread_pool_cleanup(sm_thread_pool *pool) {
  // Shut down all threads gracefully
  size_t eltsize = pool->q.element_size;

  SM_AUTO(uint8_t) *shutdown_job = sm_calloc(eltsize, 1);
  memset(shutdown_job, 0xff, eltsize);

  // Shutdown jobs must submit.
  for (int i = 0; i < SM_THREAD_POOL_THREADS; ++i)
    sm_thread_pool_must_submit(pool, shutdown_job);

  // And now wait for all threads to join
  for (int i = 0; i < SM_THREAD_POOL_THREADS; ++i)
    pthread_join(pool->workers[i], NULL);

  // And now free the queue
  free_sm_concurrent_queue(&pool->q);
  // free up the args struct
  sm_free(pool->args);
  sm_semaphore_close(pool->sema);
}

bool sm_thread_pool_submit(sm_thread_pool *pool, void *job) {
  bool pushed = sm_concurrent_queue_push(&pool->q, job);

  // Increment the number of pending jobs.
  atomic_fetch_add_explicit(&pool->pending, 1, memory_order_relaxed);

  // Post that there is work to be done.
  int err = sm_semaphore_post(pool->sema);
  if (err != 0) {
    SM_FATAL("sm_semaphore_post failed with %d\n", err);
  }

  return pushed;
}

void sm_thread_pool_must_submit(sm_thread_pool *pool, void *job) {
  struct timespec sleep = {
      .tv_sec = 0,
      .tv_nsec = 1000, // 1 us
  };
  bool submitted = sm_thread_pool_submit(pool, job);
  while (!submitted) {
    nanosleep(&sleep, &sleep);
    submitted = sm_thread_pool_submit(pool, job);
  }
}

// Just wait until all the jobs are serviced.
void sm_thread_pool_fence(sm_thread_pool *pool) {
  struct timespec sleep = {
      .tv_sec = 0,
      .tv_nsec = 100, // 0.1 us
  };

  int expected = 0;
  while (!atomic_compare_exchange_weak(&pool->pending, &expected, 0)) {
    nanosleep(&sleep, &sleep);
    expected = 0;
  }
}
