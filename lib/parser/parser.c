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
#include "smithy/stdlib/hash_table.h"

#define ABS(integer) ((integer) < 0 ? -(integer) : (integer))

void sm_parser_cleanup(sm_parser_context *ctx) {
  for (size_t i = 0; i < ctx->num_exprs; ++i) {
    sm_free(ctx->registered_exprs[i].token_kinds);
    sm_free(ctx->registered_exprs[i].token_fmts);
  }
  sm_free(ctx->registered_exprs);
  sm_free(ctx->expr_kinds);

  sm_lexer_cleanup(ctx->lexer);
  sm_free(ctx->lexer);
}

static const uint32_t literal_token_kind = SM_TOKEN_KIND_USER_START;
static const uint32_t question_mark_token_kind = SM_TOKEN_KIND_USER_START + 1;
static const uint32_t expr_token_kind = SM_TOKEN_KIND_USER_START + 2;
static const uint32_t literal_expr_token_kind = SM_TOKEN_KIND_USER_START + 3;
static const uint32_t simple_expr_token_kind = SM_TOKEN_KIND_USER_START + 4;
static const uint32_t variadic_exprs_token_kind = SM_TOKEN_KIND_USER_START + 5;

// Added to SM_TOKEN_KIND_USER_START to determine the kind of tokens the parser
// will register.
static uint32_t token_kind_base = 6;

sm_token_kind internal_toks[] = {
    // Literals
    {.kind = literal_token_kind, .fmt = sm_buffer_alias_str("` `")},
    // Optionals
    {.kind = question_mark_token_kind, .fmt = sm_buffer_alias_str("?")},
    // Expressions
    {.kind = expr_token_kind, .fmt = sm_buffer_alias_str("< >")},
    // Literal expressions
    {.kind = literal_expr_token_kind, .fmt = sm_buffer_alias_str("<l: >")},
    // Simple expressions
    {.kind = simple_expr_token_kind, .fmt = sm_buffer_alias_str("<s: >")},
    // Variadic number of expressions
    {.kind = variadic_exprs_token_kind, .fmt = sm_buffer_alias_str("[< >]")},
};

static void expr_kind_to_internal(sm_lexer_context *lexer,
                                  sm_expression_kind *k,
                                  sm_hash_table *seen_tokens,
                                  sm_parser_expr_ctx *internal) {
  sm_lexer_set_buffer(lexer, k->spelling);
  sm_token tok = sm_lexer_lex(lexer);
  int64_t n = 0;
  int64_t variadic = 1;
  while (tok.kind != SM_TOKEN_KIND_EOF) {
    sm_buffer spelling = sm_empty_buffer;
    uint32_t token_kind = SM_TOKEN_KIND_INVALID;

    if (tok.kind == variadic_exprs_token_kind) {
      variadic = -1;
    }

    // Handle tokens marked as optional.
    if (tok.kind == question_mark_token_kind) {
      internal->token_kinds[n - 1] *= -1;
      tok = sm_lexer_lex(lexer);
      continue;
    }

    if (tok.kind == literal_token_kind) {
      // The token the *parser* cares about is the bit inside the quotes.
      spelling = sm_buffer_alias(sm_buffer_begin(tok.spelling) + 1,
                                 sm_buffer_length(tok.spelling) - 2);
    }

    // If the token is an actual literal, then use the token's literal kind.
    sm_buffer found_token_kind;
    if (SM_TOKEN_IS_LITERAL(tok)) {
      token_kind = SM_TOKEN_KIND_LITERAL;
    } else if (tok.kind == expr_token_kind ||
               tok.kind == literal_expr_token_kind ||
               tok.kind == simple_expr_token_kind ||
               tok.kind == variadic_exprs_token_kind) {
      token_kind = tok.kind;
    } else if (sm_hash_table_get_alias(seen_tokens, spelling,
                                       &found_token_kind)) {
      token_kind = *(uint32_t *)found_token_kind.data;
    } else {
      token_kind = SM_TOKEN_KIND_USER_START + token_kind_base++;
      sm_hash_table_put(
          seen_tokens, spelling,
          sm_buffer_alias((uint8_t *)&token_kind, sizeof(uint32_t)));
    }

    internal->token_kinds = sm_safe_realloc_array(internal->token_kinds, n + 1);
    internal->token_kinds[n] = token_kind;
    internal->token_fmts = sm_safe_realloc_array(internal->token_fmts, n + 1);
    internal->token_fmts[n] = spelling;
    ++n;
    tok = sm_lexer_lex(lexer);
  }

  internal->num_tokens = n * variadic;
}

void sm_parser_register_exprs(sm_parser_context *ctx,
                              sm_diagnostic_engine_context *diag,
                              sm_expression_kind *exprs, size_t num_exprs) {
  SM_AUTO(sm_lexer_context)
  internal_lexer = {
      0,
  };
  SM_AUTO(sm_hash_table) seen_tokens;
  sm_hash_table_init(&seen_tokens);
  sm_lexer_register_tokens(&internal_lexer, internal_toks,
                           sizeof(internal_toks) / sizeof(sm_token_kind));
  ctx->registered_exprs = sm_calloc(num_exprs, sizeof(*ctx->registered_exprs));
  ctx->expr_kinds = sm_calloc(num_exprs, sizeof(*ctx->expr_kinds));
  ctx->num_exprs = num_exprs;
  ctx->lexer = sm_malloc(sizeof(sm_lexer_context));
  ctx->lexer->diag = diag;
  for (size_t i = 0; i < num_exprs; ++i) {
    expr_kind_to_internal(&internal_lexer, &exprs[i], &seen_tokens,
                          &ctx->registered_exprs[i]);
    ctx->expr_kinds[i] = exprs[i].kind;
  }

  for (size_t i = 0; i < num_exprs; ++i) {
    size_t end = ABS(ctx->registered_exprs[i].num_tokens);
    for (size_t j = 0; j < end; ++j) {
      sm_token_kind k = {
          .kind = ABS(ctx->registered_exprs[i].token_kinds[j]),
          .fmt = ctx->registered_exprs[i].token_fmts[j],
      };
      sm_lexer_register_tokens(ctx->lexer, &k, 1);
    }
  }

  // Sort the expressions by their first token, longest first.
  sm_parser_expr_ctx tmp;
  uint32_t tmp_expr_kind;
  size_t swap_idx; // Move element at swap_idx to the current iterator.

  for (size_t i = 0; i < ctx->num_exprs; ++i) {
    // Find the maximum element in this part of the subarray. Count by number of
    // tokens and length of the spelling.
    size_t buflen = sm_buffer_length(ctx->registered_exprs[i].token_fmts[0]);
    size_t ntoks = ABS(ctx->registered_exprs[i].num_tokens);
    tmp = ctx->registered_exprs[i];
    swap_idx = i;
    for (size_t j = i + 1; j < ctx->num_exprs; ++j) {
      if (ntoks < ABS(ctx->registered_exprs[j].num_tokens) ||
          (ntoks == ABS(ctx->registered_exprs[j].num_tokens) &&
           buflen < sm_buffer_length(ctx->registered_exprs[j].token_fmts[0]))) {
        buflen = sm_buffer_length(ctx->registered_exprs[j].token_fmts[0]);
        ntoks = ABS(ctx->registered_exprs[j].num_tokens);
        tmp = ctx->registered_exprs[j];
        tmp_expr_kind = ctx->expr_kinds[j];
        swap_idx = j;
        continue;
      }
    }
    // Place it at the current iterator.
    if (swap_idx != i) {
      ctx->registered_exprs[swap_idx] = ctx->registered_exprs[i];
      ctx->registered_exprs[i] = tmp;
      ctx->expr_kinds[swap_idx] = ctx->expr_kinds[i];
      ctx->expr_kinds[i] = tmp_expr_kind;
    }
  }
}

static sm_expression *parse_literal(sm_parser_context *ctx,
                                    sm_expression *parent) {
  if (!SM_TOKEN_IS_LITERAL(ctx->current_token)) {
    return NULL;
  }

  sm_expression *out = sm_malloc(sizeof(sm_expression));
  *out = (sm_expression){.tree = {.parent = (sm_itree *)parent},
                         .kind = SM_LITERAL_EXPR_KIND,
                         .loc = {{sm_buffer_begin(ctx->current_token.spelling)},
                                 {sm_buffer_end(ctx->current_token.spelling)}}};
  // Lex the next token.
  ctx->current_token = sm_lexer_lex(ctx->lexer);
  return out;
}

// Parse simple expressions - so no keywords.
static sm_expression *parse_simple_expression(sm_parser_context *ctx,
                                              sm_expression *parent) {
  for (size_t i = 0; i < ctx->num_exprs; ++i) {
    if (!SM_IS_SIMPLE_EXPR(ctx->expr_kinds[i])) {
      continue;
    }

    if (SM_TOKEN_IS_LITERAL(ctx->current_token)) {
      return parse_literal(ctx, parent);
    }

    if (ctx->registered_exprs[i].token_kinds[0] != ctx->current_token.kind) {
      continue;
    }

    if (ctx->expr_kinds[i] == SM_ARRAY_EXPR_KIND) {
      // First token is opener, second token is delimiter, third token is
      // closer.
      sm_expression *out = sm_malloc(sizeof(sm_expression));
      *out = (sm_expression){
          .tree = {.parent = (sm_itree *)parent},
          .kind = SM_ARRAY_EXPR_KIND,
          .loc = {{sm_buffer_begin(ctx->current_token.spelling)}}};
      // Lex the opening token.
      ctx->current_token = sm_lexer_lex(ctx->lexer);
      while (ctx->current_token.kind !=
             ctx->registered_exprs[i].token_kinds[2]) {
        if (ctx->current_token.kind ==
            ctx->registered_exprs[i].token_kinds[1]) {
          ctx->current_token = sm_lexer_lex(ctx->lexer);
          continue;
        }
        sm_expression *subexpr = parse_simple_expression(ctx, out);
        sm_itree_take_child((sm_itree *)out, (sm_itree *)subexpr);
      }
      out->loc.end.ptr = sm_buffer_end(ctx->current_token.spelling);
      // Consume the closing token.
      ctx->current_token = sm_lexer_lex(ctx->lexer);
      return out;
    }

    if (ctx->expr_kinds[i] == SM_MAP_EXPR_KIND) {
      // First token is opener, second token is mapper, third token is
      // delimiter, fourth token is closer.
      sm_expression *out = sm_malloc(sizeof(sm_expression));
      *out = (sm_expression){
          .tree = {.parent = (sm_itree *)parent},
          .kind = SM_MAP_EXPR_KIND,
          .loc = {{sm_buffer_begin(ctx->current_token.spelling)}}};
      // Lex the opening token.
      ctx->current_token = sm_lexer_lex(ctx->lexer);
      while (ctx->current_token.kind !=
             ctx->registered_exprs[i].token_kinds[3]) {
        // If it's a mapper or delimiter, go to the next token.
        if (ctx->current_token.kind ==
                ctx->registered_exprs[i].token_kinds[2] ||
            ctx->current_token.kind ==
                ctx->registered_exprs[i].token_kinds[1]) {
          ctx->current_token = sm_lexer_lex(ctx->lexer);
          continue;
        }
        sm_expression *subexpr = parse_simple_expression(ctx, out);
        sm_itree_take_child((sm_itree *)out, (sm_itree *)subexpr);
      }
      out->loc.end.ptr = sm_buffer_end(ctx->current_token.spelling);
      // Consume the closing token.
      ctx->current_token = sm_lexer_lex(ctx->lexer);
      return out;
    }

    if (ctx->expr_kinds[i] == SM_STRING_EXPR_KIND) {
      sm_expression *out = sm_malloc(sizeof(sm_expression));
      *out = (sm_expression){
          .tree = {.parent = (sm_itree *)parent},
          .kind = SM_STRING_EXPR_KIND,
          .loc = {{sm_buffer_begin(ctx->current_token.spelling)},
                  {sm_buffer_end(ctx->current_token.spelling)}}};
      // Lex the full token to advance past it.
      ctx->current_token = sm_lexer_lex(ctx->lexer);
      return out;
    }
  }

  return NULL;
}

static void free_sm_expression(sm_expression **expr) { sm_free(*expr); }

static sm_expression *parse_compound_expression(sm_parser_context *ctx,
                                                sm_expression *parent) {
  uint8_t *expr_start = sm_buffer_begin(ctx->current_token.spelling);
  sm_expression *o = NULL;
  SM_AUTO(sm_expression) *out = sm_malloc(sizeof(sm_expression));
  *out = (sm_expression){.tree = {.parent = (sm_itree *)parent},
                         .kind = SM_INVALID_EXPR_KIND};
  sm_token last_expr_token = ctx->current_token;

  // Check if the first token of any expression matches this one.
  for (size_t i = 0; i < ctx->num_exprs; ++i) {
    if (ctx->registered_exprs[i].token_kinds[0] != ctx->current_token.kind &&
        // These should only show up at the very end, so it would hit these only
        // if it hasn't matched a longer starting token.
        ctx->registered_exprs[i].token_kinds[0] != literal_expr_token_kind &&
        ctx->registered_exprs[i].token_kinds[0] != simple_expr_token_kind) {
      continue;
    }

    if (ctx->registered_exprs[i].token_kinds[0] == literal_expr_token_kind) {
      sm_expression *literal = parse_literal(ctx, out);
      sm_itree_take_child((sm_itree *)out, (sm_itree *)literal);
    } else if (ctx->registered_exprs[i].token_kinds[0] ==
               simple_expr_token_kind) {
      sm_expression *expr = parse_simple_expression(ctx, out);
      sm_itree_take_child((sm_itree *)out, (sm_itree *)expr);
    }

    ctx->current_token = sm_lexer_lex(ctx->lexer);
    sm_parser_expr_ctx current_expr_ctx = ctx->registered_exprs[i];
    bool is_variadic = current_expr_ctx.num_tokens < 0;
    size_t end = is_variadic ? -current_expr_ctx.num_tokens
                             : current_expr_ctx.num_tokens;
    bool successful = true;
    for (size_t j = 1; j < end; ++j) {
      int64_t token_kind = current_expr_ctx.token_kinds[j];
      bool is_optional = token_kind < 0;
      uint32_t abs_token_kind = ABS(token_kind);

      // If it's a literal expression token, parse that literal.
      if (abs_token_kind == literal_expr_token_kind) {
        sm_expression *expr = parse_literal(ctx, out);
        if (expr) {
          sm_itree_take_child((sm_itree *)out, (sm_itree *)expr);
          continue;
        }
      }

      // If it's a simple expression token, then parse that expression.
      if (abs_token_kind == simple_expr_token_kind) {
        sm_expression *expr = parse_simple_expression(ctx, out);
        if (expr) {
          sm_itree_take_child((sm_itree *)out, (sm_itree *)expr);
          continue;
        }
      }

      // If it's an expression token, then parse that expression.
      if (abs_token_kind == expr_token_kind) {
        sm_expression *expr = parse_compound_expression(ctx, out);
        if (expr) {
          sm_itree_take_child((sm_itree *)out, (sm_itree *)expr);
          continue;
        }
      }

      if (abs_token_kind == variadic_exprs_token_kind) {
        int64_t closing_token_kind = current_expr_ctx.token_kinds[j + 1];
        sm_expression *expr = NULL;
        // While we haven't found the closing token yet, continue parsing.
        bool failure = false;
        while (ctx->current_token.kind != closing_token_kind) {
          expr = parse_compound_expression(ctx, out);
          if (!expr) {
            failure = true;
            break;
          }
          sm_itree_take_child((sm_itree *)out, (sm_itree *)expr);
        }
        if (!failure) {
          continue;
        }
      }

      // If it's an optional token, then it doesn't have to match. Otherwise if
      // the token doesn't match; failure.
      if (abs_token_kind != ctx->current_token.kind) {
        if (is_optional) {
          // Don't lex the next token, it's an optional
          continue;
        }
        sm_diagnostic_engine_emit_error(
            ctx->lexer->diag, (sm_location){ctx->current_token.spelling.data},
            sm_buffer_alias_str("Did not find expected token.\n"));
        successful = false;
        break;
      }

      // If it's a literal then dispatch to the correct function and hook it up
      // to the tree.
      if (SM_TOKEN_IS_LITERAL(ctx->current_token)) {
        sm_expression *literal = parse_literal(ctx, out);
        if (!literal) {
          return NULL;
        }
        sm_itree_take_child((sm_itree *)out, (sm_itree *)literal);
      }

      // Lex the next token.
      last_expr_token = ctx->current_token;
      ctx->current_token = sm_lexer_lex(ctx->lexer);
    }
    if (successful) {
      out->kind = ctx->expr_kinds[i];
      out->loc = (sm_loc_range){{expr_start},
                                {sm_buffer_end(last_expr_token.spelling)}};
      o = sm_malloc(sizeof(sm_expression));
      *o = *out;
      break;
    } else {
      sm_diagnostic_engine_emit_error(
          ctx->lexer->diag, (sm_location){ctx->current_token.spelling.data},
          sm_buffer_alias_str("Parsing the current token failed.\n"));
      sm_free(out);
      out = NULL;
      break;
    }
  }

  return o;
}

sm_expression *sm_parser_parse(sm_parser_context *ctx) {
  ctx->current_token = sm_lexer_lex(ctx->lexer);
  sm_expression *root_expr = sm_malloc(sizeof(sm_expression));
  root_expr->kind = SM_ROOT_EXPR_KIND;
  root_expr->loc = (sm_loc_range){{sm_buffer_begin(ctx->lexer->current_buffer)},
                                  {sm_buffer_end(ctx->lexer->current_buffer)}};
  while (ctx->current_token.kind != SM_TOKEN_KIND_EOF) {
    // If the current token is a literal, then parse the literal.
    if (SM_TOKEN_IS_LITERAL(ctx->current_token)) {
      parse_literal(ctx, root_expr);
      ctx->current_token = sm_lexer_lex(ctx->lexer);
      continue;
    }

    sm_expression *expr = parse_compound_expression(ctx, root_expr);
    if (!expr) {
      sm_diagnostic_engine_emit_error(
          ctx->lexer->diag, (sm_location){ctx->current_token.spelling.data},
          sm_buffer_alias_str("Expression parsing failed.\n"));
      return NULL;
    }
    sm_itree_take_child((sm_itree *)root_expr, (sm_itree *)expr);
  }

  return root_expr;
}
