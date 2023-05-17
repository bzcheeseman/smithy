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

#include "smithy/stdlib/buffer.h"

#include <stdbool.h>

typedef struct sm_file_ sm_file;
struct sm_file_ {
  // Write contents of buffer to specified file
  bool (*write)(const sm_file *file, const sm_buffer buf);
  // Read contents of file into the end of the specified buffer
  bool (*read)(const sm_file *file, sm_buffer *buf);
  // Get the size of the file
  size_t (*size)(const sm_file *file);
  // Map the contents of the file and return them in the buffer. If size is
  // specified (i.e. size > 0), it truncates the file to the specified size.
  // Then the returned buffer will be of length 'size'
  sm_buffer (*map)(const sm_file *file, size_t size);
  void (*unmap)(const sm_buffer buf);

  // Get the descriptor from the file. Returns -1 on error.
  int (*descriptor)(const sm_file *file);

  // OS handle for the file, to be used by the implementation
  uint64_t handle;
};

/// Open a file at `path` with `mode`.
sm_file *sm_open(const char *path, const char *mode);
/// Close the file.
void sm_close(sm_file *f);

/// sm_file aliases for stderr/stdout.
sm_file *sm_stderr(void);
sm_file *sm_stdout(void);

/// Needed for SM_AUTO macro - close the file rather than freeing though.
static inline void free_sm_file(sm_file **f) {
  if (f) {
    sm_close(*f);
  }
}
