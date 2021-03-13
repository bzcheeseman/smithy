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

#include "smithy/stdlib/b64.h"
#include "smithy/stdlib/buffer.h"
#include <stdio.h>

#ifndef SMITHY_TEST_RESOURCE_PATH
#error "must define path to testing resources"
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define TEST_RESOURCE(file) TOSTRING(SMITHY_TEST_RESOURCE_PATH) "/" file

#define SM_DUMP_BUFFER_B64(buf)                                                \
  do {                                                                         \
    SM_AUTO(sm_buffer) b64_enc = sm_empty_buffer;                              \
    sm_b64_encode(SM_B64_STANDARD_ENCODING, (buf), &b64_enc);                  \
    printf("sm_buffer %s {\n\t.length = %zu,\n\t.capacity = %zu,\n\t.data = "  \
           "%.*s\n}\n",                                                        \
           STRINGIFY(buf), (buf).length, (buf).capacity,                       \
           (int)sm_buffer_length(b64_enc), sm_buffer_begin(b64_enc));          \
  } while (0)

#define SM_DUMP_BUFFER_HEX(buf)                                                \
  do {                                                                         \
    printf(                                                                    \
        "sm_buffer %s {\n\t.length = %zu,\n\t.capacity = %zu,\n\t.data = [",   \
        STRINGIFY(buf), (buf).length, (buf).capacity);                         \
    for (size_t i = 0; i < (buf).length; ++i) {                                \
      printf(" %.2x", *(sm_buffer_begin((buf)) + i));                          \
    }                                                                          \
    printf(" ]\n}\n");                                                         \
  } while (0)
