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

#include <stddef.h>

/// Standard libc memset/memcpy/memmove provided here to reduce dependence on
/// libc.
void sm_memset(void *ptr, unsigned char c, size_t n);
void sm_memcpy(void *dst, const void *src, size_t n);
void sm_memmove(void *dst, const void *src, size_t n);
