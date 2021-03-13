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

#include "smithy/parser/source_manager.h"

size_t sm_source_manager_open_file(sm_source_manager_context *ctx,
                                   const sm_buffer filename) {
  ctx->files = sm_safe_realloc_array(ctx->files, ctx->num_files + 1);
  ctx->files[ctx->num_files] = sm_open(sm_buffer_as_str(filename), "r");
  ctx->filebuffers =
      sm_safe_realloc_array(ctx->filebuffers, ctx->num_files + 1);
  ctx->filebuffers[ctx->num_files] =
      ctx->files[ctx->num_files]->map(ctx->files[ctx->num_files], 0);
  ctx->filenames = sm_safe_realloc_array(ctx->filenames, ctx->num_files + 1);
  ctx->filenames[ctx->num_files] = sm_buffer_clone(filename);
  return ctx->num_files++;
}

size_t sm_source_manager_alias_buffer(sm_source_manager_context *ctx,
                                      const sm_buffer filename,
                                      const sm_buffer buf) {
  ctx->files = sm_safe_realloc_array(ctx->files, ctx->num_files + 1);
  ctx->files[ctx->num_files] = NULL;
  ctx->filebuffers =
      sm_safe_realloc_array(ctx->filebuffers, ctx->num_files + 1);
  ctx->filebuffers[ctx->num_files] = buf;
  ctx->filenames = sm_safe_realloc_array(ctx->filenames, ctx->num_files + 1);
  ctx->filenames[ctx->num_files] = sm_buffer_clone(filename);
  return ctx->num_files++;
}

void sm_source_manager_cleanup(sm_source_manager_context *ctx) {
  for (size_t i = 0; i < ctx->num_files; ++i) {
    if (ctx->files[i]) {
      ctx->files[i]->unmap(ctx->filebuffers[i]);
      sm_close(ctx->files[i]);
    }

    sm_buffer_cleanup(ctx->filenames[i]);
  }
  sm_free(ctx->files);
  sm_free(ctx->filebuffers);
  sm_free(ctx->filenames);
  ctx->num_files = 0;
}

sm_file *sm_source_manager_get_file(sm_source_manager_context *ctx,
                                    size_t handle) {
  if (handle >= ctx->num_files) {
    return NULL;
  }

  return ctx->files[handle];
}

sm_buffer sm_source_manager_get_filename(sm_source_manager_context *ctx,
                                         size_t handle) {
  if (handle >= ctx->num_files) {
    return sm_empty_buffer;
  }

  return ctx->filenames[handle];
}

bool sm_source_manager_get_handle_for_loc(sm_source_manager_context *ctx,
                                          const sm_location ptr,
                                          size_t *handle) {
  for (size_t h = 0; h < ctx->num_files; ++h) {
    if (ptr.ptr >= sm_buffer_begin(ctx->filebuffers[h]) &&
        ptr.ptr < sm_buffer_end(ctx->filebuffers[h])) {
      *handle = h;
      return true;
    }
  }
  return false;
}

sm_line_and_column
sm_source_manager_get_line_and_column(sm_source_manager_context *ctx,
                                      const sm_location loc) {
  size_t handle = 0;
  if (!sm_source_manager_get_handle_for_loc(ctx, loc, &handle)) {
    return (sm_line_and_column){0, 0};
  }

  const sm_buffer filebuf = ctx->filebuffers[handle];

  // Line and column are 1-based.
  unsigned line = 1;
  unsigned column = 1;
  for (uint8_t *iter = sm_buffer_begin(filebuf), *end = sm_buffer_end(filebuf);
       iter != end && iter < loc.ptr; ++iter) {
    if (*iter == '\n') {
      ++line;
      column = 1;
      continue;
    }

    ++column;
  }

  return (sm_line_and_column){line, column};
}
