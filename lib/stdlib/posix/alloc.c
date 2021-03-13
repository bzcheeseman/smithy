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

#include "smithy/stdlib/alloc.h"
#include "smithy/stdlib/logging.h"
#include "smithy/stdlib/assert.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef SM_CALLOC_IMPL
#error "Must define calloc"
#endif

#ifndef SM_FREE_IMPL
#error "Must define free"
#endif

struct ptr {
  uint64_t sz;
};

#define STRUCT_FROM_PTR(pointer)                                               \
  ((struct ptr *)((char *)(pointer) - sizeof(struct ptr)))
#define PTR_FROM_STRUCT(s) ((void *)((char *)(s) + sizeof(struct ptr)))

void *sm_malloc(size_t size) {
  // Allocate enough space for a ptr struct
  struct ptr *out = SM_CALLOC_IMPL(1, size + sizeof(struct ptr));
  out->sz = size;
  void *ret = PTR_FROM_STRUCT(out);

  // cppcheck-suppress memleak
  return ret;
}

void *sm_calloc(size_t count, size_t size) { return sm_malloc(count * size); }

void *sm_realloc(void *p, size_t newsz) {
  void *out = sm_malloc(newsz); // Make sure unused memory is set to zero
  // If p is NULL, it's the same as malloc
  if (p == NULL) {
    return out;
  }

  // Copy over the old data
  struct ptr *ptr = STRUCT_FROM_PTR(p);
  uint64_t psz = ptr->sz;
  // Copy the lesser of the two
  memcpy(out, p, (psz > newsz ? newsz : psz));
  // Free the old pointer
  sm_free(p);
  return out;
}

void *sm_safe_realloc(void *p, size_t newsz) {
  void *tmp = sm_realloc(p, newsz);
  SM_ASSERT(tmp != NULL);
  return tmp;
}

void sm_free(void *p) {
  // free(NULL) should be OK
  if (p == NULL) {
    return;
  }

  if ((uintptr_t)p == 0xfefefefefefefefe) {
    SM_ERROR("Double free detected!\n");
    return;
  }

  struct ptr *ps = STRUCT_FROM_PTR(p);
  volatile uint8_t *iter = p;
  // Set the memory region to 0xfefefefefefefefe
  for (size_t i = 0; i < ps->sz; ++i) {
    *iter++ = 0xfe;
  }

  // Then free the struct
  SM_FREE_IMPL(ps);
}

char *sm_strdup(const char *s) {
  if (s == NULL) {
    return NULL;
  }

  size_t slen = strlen(s);
  // Malloc the new thing
  char *out = sm_malloc(slen + 1);
  // Copy the contents
  memcpy(out, s, slen);
  // Null-terminate the output. This should already have happened by sm_malloc
  // but can't hurt to be safe.
  out[slen] = 0;
  return out;
}
