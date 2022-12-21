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

#include "smithy/stdlib/logging.h"
#include "smithy/threads/thread_pool.h"
#include <stdio.h>

void work(void *arg) {
  char *s = arg;
  printf("%s\n", s);
}

#define niters 10

void simple() {
  sm_thread_pool pool;
  sm_thread_pool_init(&pool, 2, &work);
  struct timespec t = {
      .tv_sec = 0,
      .tv_nsec = 100 * 1000 * 1000, // 100 milliseconds
  };
  nanosleep(&t, &t);

  for (int i = 0; i < niters; ++i) {
    char job[2];
    snprintf(job, 2, "%d", i);
    sm_thread_pool_must_submit(&pool, job);
  }

  nanosleep(&t, &t);

  sm_thread_pool_cleanup(&pool);
}

void fence() {
  sm_thread_pool pool;
  sm_thread_pool_init(&pool, 2, &work);
  struct timespec t = {
      .tv_sec = 0,
      .tv_nsec = 100 * 1000 * 1000, // 100 milliseconds
  };
  nanosleep(&t, &t);

  for (int i = 0; i < niters - 5; ++i) {
    char job[2];
    snprintf(job, 2, "%d", i);
    sm_thread_pool_must_submit(&pool, job);
  }

  // Break and then resume
  sm_thread_pool_fence(&pool);
  // Assert there are no jobs pending anywhere.
  SM_ASSERT(pool.pending == 0);
  SM_ASSERT(sm_concurrent_queue_empty(&pool.q));

  for (int i = niters - 5; i < niters; ++i) {
    char job[2];
    snprintf(job, 2, "%d", i);
    sm_thread_pool_must_submit(&pool, job);
  }

  nanosleep(&t, &t);

  sm_thread_pool_cleanup(&pool);
}

struct bench_job {
  float lhs, rhs;
  float *sum;
};

void bench_work(void *arg) {
  struct bench_job *j = arg;
  *j->sum = j->lhs + j->rhs;
}

void bench() {
  sm_thread_pool pool;
  sm_thread_pool_init(&pool, sizeof(struct bench_job), &bench_work);
  struct timespec t = {
      .tv_sec = 0,
      .tv_nsec = 100 * 1000 * 1000, // 100 milliseconds
  };
  nanosleep(&t, &t);

  struct bench_job jobs[niters];
  float sums[niters] = {
      0,
  };
  for (int i = 0; i < niters; ++i) {
    jobs[i].lhs = (float)i + 1;
    jobs[i].rhs = (float)i + 2;
    jobs[i].sum = &sums[i];
    // Make sure that it gets submitted
    sm_thread_pool_must_submit(&pool, &jobs[i]);
  }

  sm_thread_pool_cleanup(&pool);

  for (int i = 0; i < niters; ++i) {
    float res = (float)i + 1;
    res += (float)i + 2;
    SM_ASSERT(sums[i] == res);
  }
}

int main() {
  simple();
  fence();
  bench();
}
