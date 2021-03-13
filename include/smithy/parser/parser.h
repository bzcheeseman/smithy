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

#include "smithy/parser/lexer.h"
#include "smithy/parser/source_manager.h"
#include "smithy/stdlib/tree.h"

typedef struct {
  // The children here will be empty if this expression is a
  // leaf. Leaf expressions are single tokens.
  sm_itree tree;
  uint32_t kind;
  sm_loc_range loc;
} sm_expression;

#define SM_INVALID_EXPR_KIND 0
#define SM_LITERAL_EXPR_KIND 1
#define SM_ARRAY_EXPR_KIND 2
#define SM_MAP_EXPR_KIND 3
#define SM_STRING_EXPR_KIND 4
#define SM_IS_SIMPLE_EXPR(kind) ((kind) >= 1 && (kind) <= 4)

#define SM_ROOT_EXPR_KIND 5

typedef struct {
  uint32_t kind;
  // Spelling here means a string.
  // "`let` name `:`? type? `=` var `;`"
  // "`struct` name `{` [exprs] `}` `;`"
  // "`module` `{` [exprs] `}` `;`"
  // "`[` [values] `]`
  // "`(` [key `:` value] `)`
  // [{ string }] or "string"
  sm_buffer spelling;
} sm_expression_kind;

// None of the buffers inside this object are owned by the object! Do not free!
typedef struct {
  int64_t *token_kinds; // this is an int64 because optionals are negative
  sm_buffer *token_fmts;
  int64_t num_tokens; // Number of tokens in an expression.
} sm_parser_expr_ctx;

typedef struct {
  uint32_t *expr_kinds;
  sm_parser_expr_ctx *registered_exprs;
  size_t num_exprs;

  sm_lexer_context *lexer;
  sm_token current_token;
} sm_parser_context;

void sm_parser_cleanup(sm_parser_context *ctx);

// Needed for SM_AUTO.
static inline void free_sm_parser_context(sm_parser_context *ctx) {
  sm_parser_cleanup(ctx);
}

void sm_parser_register_exprs(sm_parser_context *ctx,
                              sm_diagnostic_engine_context *diag,
                              sm_expression_kind *exprs, size_t num_exprs);

static inline void sm_parser_set_buffer(sm_parser_context *ctx,
                                        const sm_buffer buffer) {
  sm_lexer_set_buffer(ctx->lexer, buffer);
}

sm_expression *sm_parser_parse(sm_parser_context *ctx);
