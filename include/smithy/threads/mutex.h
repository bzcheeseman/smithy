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

#if SMITHY_USE_POSIX
#include <pthread.h>
typedef pthread_mutex_t sm_mutex;
#else
#include <stdatomic.h>
typedef atomic_flag sm_mutex;
#endif

int sm_mutex_init(sm_mutex *mutex);
int sm_mutex_destroy(sm_mutex *mutex);
int sm_mutex_lock(sm_mutex *mutex);
int sm_mutex_unlock(sm_mutex *mutex);
