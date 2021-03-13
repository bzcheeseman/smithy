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

#include "smithy/parser/source_manager.h"
#include "smithy/stdlib/filesystem.h"

typedef struct {
  sm_file *notes;
  sm_file *errs;
  sm_source_manager_context *srcmgr_ctx;
} sm_diagnostic_engine_context;

void sm_diagnostic_engine_emit_error(sm_diagnostic_engine_context *ctx,
                                     const sm_location loc,
                                     const sm_buffer error);
void sm_diagnostic_engine_emit_note(sm_diagnostic_engine_context *ctx,
                                    const sm_location loc,
                                    const sm_buffer note);
