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

#include "smithy/threads/mutex.h"
#include "smithy/threads/yield.h"

int sm_mutex_init(sm_mutex *mutex) {
#if SMITHY_USE_POSIX
  return pthread_mutex_init(mutex, NULL);
#else
  return sm_mutex_unlock(mutex);
#endif
}

int sm_mutex_destroy(sm_mutex *mutex) {
#if SMITHY_USE_POSIX
  return pthread_mutex_destroy(mutex);
#else
  // Wait until the mutex becomes available (spinlock). The standard says
  // undefined behavior if the mutex is locked.
  while (atomic_flag_test_and_set(mutex))
    ;
  return 0;
#endif
}

int sm_mutex_lock(sm_mutex *mutex) {
#if SMITHY_USE_POSIX
  return pthread_mutex_lock(mutex);
#else
  // Wait until the mutex becomes available (spinlock).
  while (atomic_flag_test_and_set(mutex)) {
    int ret = sm_sched_yield;
    // Handle potential errors from sched_yield
    if (ret != 0) {
      return ret;
    }
  }
  return 0;
#endif
}

int sm_mutex_unlock(sm_mutex *mutex) {
#if SMITHY_USE_POSIX
  return pthread_mutex_unlock(mutex);
#else
  atomic_flag_clear(mutex);
  return 0;
#endif
}
