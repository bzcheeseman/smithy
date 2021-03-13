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

#ifndef SM_THREAD_POOL_THREADS
#define SM_THREAD_POOL_THREADS 4
#endif

#include "smithy/stdlib/queue.h"
#include "smithy/threads/concurrent_queue.h"
#include "smithy/threads/mutex.h"
#include "smithy/threads/semaphore.h"

#include <pthread.h>
#include <stdatomic.h>

typedef struct {
  sm_concurrent_queue q;
  atomic_int pending;
  void *args;
  sm_semaphore *sema;
  pthread_t workers[SM_THREAD_POOL_THREADS];
} sm_thread_pool;

typedef void (*worker_fn)(void *args);

void sm_thread_pool_init(sm_thread_pool *pool, size_t work_elt_size,
                         worker_fn worker);
void sm_thread_pool_cleanup(sm_thread_pool *pool);

// Returns false if the work queue is full
bool sm_thread_pool_submit(sm_thread_pool *pool, void *job);
void sm_thread_pool_must_submit(sm_thread_pool *pool, void *job);

void sm_thread_pool_fence(sm_thread_pool *pool);
