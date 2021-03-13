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
#include <stdbool.h>

// Not quite as good as LLVM's pointerintpair because we don't have templates,
// so they can't be nested. We also can't do as much checking, so it's up to the
// user to know how many bits they can use.
#define SM_PTR_INT_PAIR(bits)                                                  \
  struct ptr_int_pair_##bits {                                                 \
    uintptr_t value;                                                           \
  }

#define SM_PTR_INT_PAIR_PTR_MASK_(bits) ~(uintptr_t)((1ull << (bits)) - 1)
#define SM_PTR_INT_PAIR_INT_MASK_(bits) (uintptr_t)((1ull << (bits)) - 1)

typedef uintptr_t sm_ptr_int_pair;

#define SM_PAIR_SET_PTR(obj, bits, ptr)                                        \
  ((obj).value =                                                               \
       (uintptr_t)(ptr) | ((obj).value & ~SM_PTR_INT_PAIR_PTR_MASK_(bits)))
#define SM_PAIR_GET_PTR(obj, bits)                                             \
  ((obj).value & SM_PTR_INT_PAIR_PTR_MASK_(bits))

#define SM_PAIR_SET_INT(obj, bits, i)                                          \
  ((obj).value = ((obj).value & ~SM_PTR_INT_PAIR_INT_MASK_(bits)) | (i))
#define SM_PAIR_GET_INT(obj, bits)                                             \
  ((obj).value & SM_PTR_INT_PAIR_INT_MASK_(bits))

#define SM_DEFINE_PTR_INT_PAIR(bits, intname)                                  \
  typedef SM_PTR_INT_PAIR(bits) sm_ptr_u##bits##_pair;                         \
  static inline void sm_ptr_u##bits##_pair_set_ptr(                            \
      sm_ptr_u##bits##_pair *pair, void *ptr) {                                \
    SM_PAIR_SET_PTR(*pair, (bits), ptr);                                       \
  }                                                                            \
  static inline void *sm_ptr_u##bits##_pair_get_ptr(                           \
      sm_ptr_u##bits##_pair pair) {                                            \
    return (void *)(SM_PAIR_GET_PTR(pair, (bits)));                            \
  }                                                                            \
  static inline void sm_ptr_u##bits##_pair_set_int(                            \
      sm_ptr_u##bits##_pair *pair, intname i) {                                \
    SM_PAIR_SET_INT(*pair, (bits), i);                                         \
  }                                                                            \
  static inline intname sm_ptr_u##bits##_pair_get_int(                         \
      sm_ptr_u##bits##_pair pair) {                                            \
    return SM_PAIR_GET_INT(pair, (bits));                                      \
  }

SM_DEFINE_PTR_INT_PAIR(1, bool)

#define sm_ptr_u1_pair_true(val)                                             \
  (sm_ptr_u1_pair) { .value = (uintptr_t)(val) | (uintptr_t)1 }
#define sm_ptr_u1_pair_false(val)                                            \
  (sm_ptr_u1_pair) { .value = (uintptr_t)(val) | (uintptr_t)0 }

SM_DEFINE_PTR_INT_PAIR(12, uint16_t)
#define sm_ptr_u12_pair_null (sm_ptr_u12_pair) { .value = (uintptr_t)NULL }
