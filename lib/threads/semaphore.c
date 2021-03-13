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

#include "smithy/threads/semaphore.h"
#include "smithy/stdlib/alloc.h"
#include "smithy/threads/yield.h"
#include <stdatomic.h>

sm_semaphore *sm_semaphore_open(int32_t value) {
#if SMITHY_USE_POSIX
  return sem_open("smithy.posix.semaphore", O_CREAT, S_IRUSR | S_IWUSR, value);
#else
  sm_semaphore *out = sm_malloc(sizeof(sm_semaphore));
  if (out == NULL) {
    return NULL;
  }
  // Clear out the mutex and the value.
  atomic_flag_clear(&out->mutex);
  atomic_init(&out->value, value);
  return out;
#endif
}

int sm_semaphore_close(sm_semaphore *sem) {
#if SMITHY_USE_POSIX
  int ret = sem_close(sem);
  if (ret != 0) {
    return ret;
  }
  return sem_unlink("smithy.posix.semaphore");
#else
  // Note that this does NOT wait until the semaphore is cleared.
  sm_free(sem);
  return 0;
#endif
}

int sm_semaphore_wait(sm_semaphore *sem) {
#if SMITHY_USE_POSIX
  return sem_wait(sem);
#else
  // Acquire the mutex in the semaphore.
  while (atomic_flag_test_and_set(&sem->mutex)) {
    int ret = sm_sched_yield;
    // Handle potential errors from sched_yield
    if (ret != 0) {
      return ret;
    }
  }

  // Wait for the count to be at least 0.
  while (atomic_load(&sem->value) <= 0) {
    int ret = sm_sched_yield;
    // Handle potential errors from sched_yield
    if (ret != 0) {
      return ret;
    }
  }
  // Subtract 1 from the semaphore.
  atomic_fetch_sub(&sem->value, 1);
  // And release the mutex.
  atomic_flag_clear(&sem->mutex);
  return 0;
#endif
}

int sm_semaphore_post(sm_semaphore *sem) {
#if SMITHY_USE_POSIX
  return sem_post(sem);
#else
  (void)atomic_fetch_add(&sem->value, 1);
  return 0;
#endif
}
