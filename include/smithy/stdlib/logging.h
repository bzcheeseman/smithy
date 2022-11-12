//
// Copyright 2020 Aman LaChapelle
// Full license at keyderiver/LICENSE.txt
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

#include <stdarg.h>
#include <stdlib.h>

typedef enum {
  kDEBUG = 0,
  kINFO = 1,
  kERROR = 2,
  kFATAL = 3,
} sm_log_level;

// Args are ctx, format, args. It MUST be able to handle an empty va_list.
typedef void (*log_fn)(void *, const char *, va_list);

/// Set the log function and log context variables.
void set_log_fn(log_fn fn);
void set_log_ctx(void *ctx);

void sm_log_expr(sm_log_level level, char *fmt, ...);

/// This macro gets defined by the build system for release builds.
#ifndef SM_MINIMUM_LOG
#define SM_MINIMUM_LOG kDEBUG
#endif

#if SM_MINIMUM_LOG > kDEBUG
#define SM_DEBUG(...) (void)
#else
#define SM_DEBUG(...)                                                          \
  do {                                                                         \
    sm_log_expr(kDEBUG, __VA_ARGS__);                                          \
  } while (0)
#endif

#if SM_MINIMUM_LOG > kINFO
#define SM_INFO(...) (void)
#else
#define SM_INFO(...)                                                           \
  do {                                                                         \
    sm_log_expr(kINFO, __VA_ARGS__);                                           \
  } while (0)
#endif

/// Error and fatal logs are always logged

#define SM_ERROR(...)                                                          \
  do {                                                                         \
    sm_log_expr(kERROR, __VA_ARGS__);                                          \
  } while (0)

#define SM_FATAL(...)                                                          \
  do {                                                                         \
    sm_log_expr(kFATAL, __VA_ARGS__);                                          \
    abort();                                                                   \
  } while (0)
