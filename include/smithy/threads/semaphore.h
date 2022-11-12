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

#include <stdint.h>

#if SMITHY_USE_POSIX
#include <semaphore.h>
typedef sem_t sm_semaphore;
#else
#include <stdatomic.h>
typedef struct {
  volatile atomic_int value;
  volatile atomic_flag mutex;
} sm_semaphore;
#define SEM_FAILED NULL
#endif

/// Smithy semaphore API.
sm_semaphore *sm_semaphore_open(int32_t value);
int sm_semaphore_close(sm_semaphore *sem);
int sm_semaphore_wait(sm_semaphore *sem);
int sm_semaphore_post(sm_semaphore *sem);
