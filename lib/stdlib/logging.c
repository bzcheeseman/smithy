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

#include "smithy/stdlib/logging.h"
#include "smithy/stdlib/buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SM_NO_STDLIB
void default_log_fn(void *ctx, const char *fmt, va_list args) {
  (void)ctx;
  vfprintf(stderr, fmt, args);
}

static log_fn log_func = &default_log_fn;
#else
static log_fn log_func = NULL;
#endif // SM_NO_STDLIB

static void *log_ctx = NULL;

void sm_set_log_fn(log_fn fn) { log_func = fn; }

void sm_set_log_ctx(void *ctx) { log_ctx = ctx; }

static char *lvls[] = {"[DEBUG] ", "[INFO] ", "[ERROR] ", "[FATAL] "};

void sm_log_expr(sm_log_level level, char *fmt, ...) {
  // Can't do anything with no log func
  if (!log_func) {
    return;
  }

  char *lvl = lvls[level];

  // cppcheck-suppress va_list_usedBeforeStarted
  va_list empty = {0};
  // cppcheck-suppress va_list_usedBeforeStarted
  log_func(log_ctx, lvl, empty);

  va_list args;
  va_start(args, fmt);
  log_func(log_ctx, fmt, args);
  va_end(args);
}
