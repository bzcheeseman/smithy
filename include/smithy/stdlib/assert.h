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

#include "smithy/stdlib/logging.h"

#ifndef NDEBUG
#define SM_ASSERT(expr)                                                        \
  do {                                                                         \
    if (!(expr)) {                                                             \
      SM_FATAL("Assertion failed: " #expr " @ " __FILE__ ":%d\n", __LINE__);   \
    }                                                                          \
  } while (0)
#else
#define SM_ASSERT(expr) (void)(expr)
#endif
