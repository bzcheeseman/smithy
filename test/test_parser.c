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

#include "smithy/parser/parser.h"
#include "resources.h"

sm_expression_kind exprs[] = {
    {.kind = SM_ROOT_EXPR_KIND,
     .spelling = sm_buffer_alias_str("`let` <l:name> `:`? <l:type>? `=` <s:value> `;`")},
    {.kind = SM_ROOT_EXPR_KIND + 1,
     .spelling = sm_buffer_alias_str("`struct` <l:name> `{` [<exprs>] `}` `;`")},
    {.kind = SM_ROOT_EXPR_KIND + 2, .spelling = sm_buffer_alias_str("`// \n`")},
    {.kind = SM_ARRAY_EXPR_KIND, .spelling = sm_buffer_alias_str("`[` `,` `]`")},
    {.kind = SM_MAP_EXPR_KIND, .spelling = sm_buffer_alias_str("`(` `:` `,` `)`")},
    {.kind = SM_STRING_EXPR_KIND, .spelling = sm_buffer_alias_str("`[{ }]`")},
};

bool walk_exprs(void *, sm_itree *tree) {
  sm_expression *expr = (sm_expression *)tree;
  if (!expr || expr->kind == 3) {
    return true;
  }
  SM_DEBUG("%.*s\n", expr->loc.end.ptr - expr->loc.begin.ptr,
           expr->loc.begin.ptr);
  return true;
}

int main(int argc, char *argv[]) {
  sm_source_manager_context source_mgr = {0,};
  size_t handle = sm_source_manager_open_file(&source_mgr, sm_buffer_alias_str(TEST_RESOURCE("parser_test.tstfile")));

  sm_parser_context ctx;

  sm_diagnostic_engine_context diag;
  diag.errs = sm_stderr();
  diag.notes = sm_stdout();
  diag.srcmgr_ctx = &source_mgr;

  sm_parser_register_exprs(&ctx, &diag, exprs,
                           sizeof(exprs) / sizeof(sm_expression_kind));
  sm_buffer filebuf = sm_source_manager_get_filebuffer(&source_mgr, handle);
  sm_parser_set_buffer(&ctx, filebuf);
  sm_expression *expr = sm_parser_parse(&ctx);
  sm_itree_traverse(expr, SM_PREORDER, &walk_exprs, NULL);
  sm_itree_free(expr, NULL);

  sm_free(expr);
  sm_parser_cleanup(&ctx);
  sm_source_manager_cleanup(&source_mgr);
  sm_close(diag.errs);
  sm_close(diag.notes);
}
