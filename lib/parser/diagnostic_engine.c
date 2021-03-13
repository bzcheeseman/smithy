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

#include "smithy/parser/diagnostic_engine.h"

void sm_diagnostic_engine_emit_error(sm_diagnostic_engine_context *ctx,
                                     const sm_location loc,
                                     const sm_buffer error) {
  sm_line_and_column lc =
      sm_source_manager_get_line_and_column(ctx->srcmgr_ctx, loc);

  SM_AUTO(sm_buffer) errbuf = sm_empty_buffer;

  size_t filehandle = 0;
  if (!sm_source_manager_get_handle_for_loc(ctx->srcmgr_ctx, loc,
                                            &filehandle)) {
    sm_buffer_print(&errbuf, "[unknown]: %.*s", sm_buffer_length(error),
                    sm_buffer_as_str(error));
  } else {
    sm_buffer filename =
        sm_source_manager_get_filename(ctx->srcmgr_ctx, filehandle);

    sm_buffer_print(&errbuf, "[%.*s:%u:%u]: %.*s", sm_buffer_length(filename),
                    sm_buffer_as_str(filename), lc.line, lc.column,
                    sm_buffer_length(error), sm_buffer_as_str(error));
  }

  ctx->errs->write(ctx->errs, errbuf);
}

void sm_diagnostic_engine_emit_note(sm_diagnostic_engine_context *ctx,
                                    const sm_location loc,
                                    const sm_buffer note) {
  sm_line_and_column lc =
      sm_source_manager_get_line_and_column(ctx->srcmgr_ctx, loc);

  SM_AUTO(sm_buffer) errbuf = sm_empty_buffer;

  size_t filehandle = 0;
  if (!sm_source_manager_get_handle_for_loc(ctx->srcmgr_ctx, loc,
                                            &filehandle)) {
    sm_buffer_print(&errbuf, "[unknown]: %.*s", sm_buffer_length(note),
                    sm_buffer_as_str(note));
  } else {
    sm_buffer filename =
        sm_source_manager_get_filename(ctx->srcmgr_ctx, filehandle);

    sm_buffer_print(&errbuf, "[%.*s:%u:%u]: %.*s", sm_buffer_length(filename),
                    sm_buffer_as_str(filename), lc.line, lc.column,
                    sm_buffer_length(note), sm_buffer_as_str(note));
  }

  ctx->notes->write(ctx->notes, errbuf);
}
