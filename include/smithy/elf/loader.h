//
// Copyright 2023 Aman LaChapelle
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

#include "smithy/stdlib/buffer.h"
#include "smithy/stdlib/filesystem.h"

typedef struct {
  int (*entry)(int, char **);
} sm_runnable_elf;

static inline bool sm_elf_is_valid(sm_runnable_elf e) {
  return e.entry != NULL;
}

/// Load an ELF file and run its entrypoint. The entrypoint is assumed to have
/// a main-like signature.
sm_runnable_elf load(sm_file *elf);
