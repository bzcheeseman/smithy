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

#include "smithy/stdlib/memory.h"

#include <stdbool.h>
#include <stdint.h>

void sm_memset(void *ptr, unsigned char c, size_t n) {
  volatile unsigned char *iter = ptr;
  for (size_t i = 0; i < n; ++i) {
    *iter++ = c;
  }
}

#define MEMCPY_INCREMENT 16

void sm_memcpy(void *dst, const void *src, size_t n) {
  uint8_t *src_iter = (uint8_t *)src;
  uint8_t *dst_iter = (uint8_t *)dst;
  // floor division, then multiply to round to nearest
  size_t end = (n / MEMCPY_INCREMENT) * MEMCPY_INCREMENT;
  for (size_t i = 0; i < end;) {
#if __has_builtin(__builtin_memcpy_inline)
    __builtin_memcpy_inline(&dst_iter[i], &src_iter[i], MEMCPY_INCREMENT);
    i += MEMCPY_INCREMENT;
#else
    dst_iter[i] = src_iter[i];
    ++i;
#endif // __has_builtin(__builtin_memcpy_inline)
  }
  // Clean up the end
  for (size_t i = end; i < n; ++i) {
    dst_iter[i] = src_iter[i];
  }
}

void sm_memmove(void *dst, const void *src, size_t n) {
  // If dst < src && dst + n > src then there's overlap
  bool dst_overlap = ((uintptr_t)dst < (uintptr_t)src &&
                      ((uintptr_t)dst + n) > (uintptr_t)src);
  // If src < dst && src + n > dst then there's overlap
  bool src_overlap = ((uintptr_t)src < (uintptr_t)dst &&
                      ((uintptr_t)src + n) > (uintptr_t)dst);

  // No overlap => use memcpy
  if (!dst_overlap && !src_overlap) {
    sm_memcpy(dst, src, n);
    return;
  }

#if __has_builtin(__builtin_memcpy_inline)
  uint8_t tmp[MEMCPY_INCREMENT] = {
      0,
  };
#endif

  uint8_t *src_iter = (uint8_t *)src;
  uint8_t *dst_iter = (uint8_t *)dst;

  if (dst < src) {
    // Copy forwards
    size_t end = (n / MEMCPY_INCREMENT) * MEMCPY_INCREMENT;
    for (size_t i = 0; i < end;) {
#if __has_builtin(__builtin_memcpy_inline)
      // Have to use tmp buffer here because otherwise we might overwrite
      __builtin_memcpy_inline(&tmp[0], &src_iter[i], MEMCPY_INCREMENT);
      __builtin_memcpy_inline(&dst_iter[i], &tmp[0], MEMCPY_INCREMENT);
#else
      for (size_t j = 0; j < MEMCPY_INCREMENT; ++j) {
        dst_iter[i + j] = src_iter[i + j];
      }
#endif // __has_builtin(__builtin_memcpy_inline)
      i += MEMCPY_INCREMENT;
    }
    // Clean up the end
    for (size_t j = end; j < n; ++j) {
      dst_iter[j] = src_iter[j];
    }
  } else {
    // Copy backwards
    int64_t begin = n - ((n / MEMCPY_INCREMENT) * MEMCPY_INCREMENT);
    for (int64_t i = n - MEMCPY_INCREMENT; i >= begin;) {
#if __has_builtin(__builtin_memcpy_inline)
      // Have to use tmp buffer here because otherwise we might overwrite
      __builtin_memcpy_inline(&tmp[0], &src_iter[i], MEMCPY_INCREMENT);
      __builtin_memcpy_inline(&dst_iter[i], &tmp[0], MEMCPY_INCREMENT);
#else
      for (int64_t j = MEMCPY_INCREMENT - 1; j >= 0; --j) {
        dst_iter[i + j] = src_iter[i + j];
      }
#endif // __has_builtin(__builtin_memcpy_inline)
      i -= MEMCPY_INCREMENT;
    }
    // Clean up the end
    for (int64_t j = begin; j >= 0; --j) {
      dst_iter[j] = src_iter[j];
    }
  }
}
