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

/// This struct should be regarded as opaque.
typedef struct {
  sm_concurrent_queue q;
  atomic_int pending;
  void *args;
  sm_semaphore *sema;
  pthread_t workers[SM_THREAD_POOL_THREADS];
} sm_thread_pool;

/// The type of a worker function on the thread pool.
typedef void (*worker_fn)(void *args);

/// Initialize a thread pool. This pool is quie static, it requires a fixed work
/// element size and a fixed worker function. That said, the worker function
/// could itself perform dispatch and the work element size could be of pointer
/// size if the user is willing to handle concurrency themselves.
void sm_thread_pool_init(sm_thread_pool *pool, size_t work_elt_size,
                         worker_fn worker);
/// Clean up the thread pool.
void sm_thread_pool_cleanup(sm_thread_pool *pool);

/// Submit a job to the thread pool. Returns false if the work queue is full.
bool sm_thread_pool_submit(sm_thread_pool *pool, void *job);
/// Tries and waits to submit a job until it's actually successful.
void sm_thread_pool_must_submit(sm_thread_pool *pool, void *job);

/// Fence the thread pool - force all jobs to quiesce.
void sm_thread_pool_fence(sm_thread_pool *pool);
