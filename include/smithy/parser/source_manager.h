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
#include "smithy/stdlib/filesystem.h"

typedef struct {
  const uint8_t *ptr;
} sm_location;

typedef struct {
  sm_location begin, end;
} sm_loc_range;

typedef struct {
  unsigned line, column;
} sm_line_and_column;

// This context owns these structures and is responsible for freeing them!
typedef struct {
  sm_buffer *filenames;
  sm_buffer *filebuffers;
  sm_file **files;
  size_t num_files;
} sm_source_manager_context;

size_t sm_source_manager_open_file(sm_source_manager_context *ctx,
                                   const sm_buffer filename);
size_t sm_source_manager_alias_buffer(sm_source_manager_context *ctx,
                                      const sm_buffer filename,
                                      const sm_buffer buf);

static inline sm_buffer
sm_source_manager_get_filebuffer(sm_source_manager_context *ctx,
                                 size_t handle) {
  return ctx->filebuffers[handle];
}

void sm_source_manager_cleanup(sm_source_manager_context *ctx);

sm_file *sm_source_manager_get_file(sm_source_manager_context *ctx,
                                    size_t handle);
sm_buffer sm_source_manager_get_filename(sm_source_manager_context *ctx,
                                         size_t handle);
bool sm_source_manager_get_handle_for_loc(sm_source_manager_context *ctx,
                                          const sm_location ptr,
                                          size_t *handle);
sm_line_and_column
sm_source_manager_get_line_and_column(sm_source_manager_context *ctx,
                                      const sm_location loc);
