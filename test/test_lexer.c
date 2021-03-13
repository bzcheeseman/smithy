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

#include "resources.h"
#include "smithy/parser/lexer.h"

const sm_token_kind tok_kinds[] = {
    {.kind = SM_TOKEN_KIND_USER_START + 1, .fmt = sm_buffer_alias_str("` `")},
    {.kind = SM_TOKEN_KIND_USER_START + 2, .fmt = sm_buffer_alias_str("?")},
    {.kind = SM_TOKEN_KIND_USER_START + 3, .fmt = sm_buffer_alias_str("=")},
    {.kind = SM_TOKEN_KIND_USER_START + 4, .fmt = sm_buffer_alias_str("// \n")},
    {.kind = SM_TOKEN_KIND_USER_START + 5, .fmt = sm_buffer_alias_str("\" \"")},
    {.kind = SM_TOKEN_KIND_USER_START + 6, .fmt = sm_buffer_alias_str("( )")},
    {.kind = SM_TOKEN_KIND_USER_START + 7, .fmt = sm_buffer_alias_str("[ ]")},
    {.kind = SM_TOKEN_KIND_USER_START + 8, .fmt = sm_buffer_alias_str("[{ }]")}};

int main(int argc, char *argv[]) {
  sm_source_manager_context source_mgr = {
      0,
  };
  size_t handle = sm_source_manager_open_file(
      &source_mgr, sm_buffer_alias_str(TEST_RESOURCE("lexer_test.tstfile")));
  sm_buffer filebuf = sm_source_manager_get_filebuffer(&source_mgr, handle);

  SM_AUTO(sm_lexer_context)
  ctx = {
      0,
  };
  sm_diagnostic_engine_context diag;
  ctx.diag = &diag;

  sm_lexer_set_buffer(&ctx, filebuf);
  sm_lexer_register_tokens(&ctx, tok_kinds,
                           sizeof(tok_kinds) / sizeof(sm_token_kind));

  sm_token tok;
  while (tok.kind != SM_TOKEN_KIND_EOF && tok.kind != SM_TOKEN_KIND_INVALID) {
    tok = sm_lexer_lex(&ctx);
    SM_DEBUG("kind: %u, spelling: %.*s\n", tok.kind,
             sm_buffer_length(tok.spelling), sm_buffer_as_str(tok.spelling));
  }

  sm_source_manager_cleanup(&source_mgr);
}
