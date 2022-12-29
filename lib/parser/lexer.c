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

#include "smithy/parser/lexer.h"
#include "smithy/parser/source_manager.h"
#include "smithy/stdlib/memory.h"
#include <ctype.h>

void sm_lexer_cleanup(sm_lexer_context *ctx) {
  sm_free(ctx->literal_kinds);
  sm_free(ctx->literal_spellings);
  ctx->num_literal = 0;

  sm_free(ctx->delimited_kinds);
  sm_free(ctx->delimiter_open);
  sm_free(ctx->delimiter_close);
  ctx->num_delimited = 0;

  ctx->current_ptr = NULL;
  ctx->current_buffer = sm_empty_buffer;
}

void sm_lexer_set_buffer(sm_lexer_context *ctx, const sm_buffer buffer) {
  ctx->current_buffer = buffer;
  ctx->current_ptr = sm_buffer_begin(ctx->current_buffer);
}

void sm_lexer_register_tokens(sm_lexer_context *ctx, const sm_token_kind *kinds,
                              size_t num_kinds) {
  for (size_t i = 0; i < num_kinds; ++i) {
    const sm_token_kind *k = &kinds[i];

    // Split the token kinds into the various lists.

    // If k->fmt does not have a space in it then it's a keyword.
    const uint8_t *space_iter = sm_buffer_find(k->fmt, ' ');
    if (space_iter == sm_buffer_end(k->fmt)) {
      // It's a keyword/literal.
      ctx->literal_kinds =
          sm_safe_realloc_array(ctx->literal_kinds, ctx->num_literal + 1);
      ctx->literal_kinds[ctx->num_literal] = k->kind;
      ctx->literal_spellings =
          sm_safe_realloc_array(ctx->literal_spellings, ctx->num_literal + 1);
      ctx->literal_spellings[ctx->num_literal] = k->fmt;
      ++ctx->num_literal;
      continue;
    }

    // Otherwise it's a pair of delimiters, so alias the buffer into 2 parts.
    // First assert each part is small enough.
    SM_ASSERT(space_iter - sm_buffer_begin(k->fmt) <= 4);
    SM_ASSERT(sm_buffer_end(k->fmt) - (space_iter + 1) <= 4);

    // And then expand the arrays in the context.
    ctx->delimited_kinds =
        sm_safe_realloc_array(ctx->delimited_kinds, ctx->num_delimited + 1);
    ctx->delimited_kinds[ctx->num_delimited] = k->kind;
    ctx->delimiter_open =
        sm_safe_realloc_array(ctx->delimiter_open, ctx->num_delimited + 1);
    sm_memcpy(ctx->delimiter_open[ctx->num_delimited], sm_buffer_begin(k->fmt),
              space_iter - sm_buffer_begin(k->fmt));
    ctx->delimiter_close =
        sm_safe_realloc_array(ctx->delimiter_close, ctx->num_delimited + 1);
    sm_memcpy(ctx->delimiter_close[ctx->num_delimited], space_iter + 1,
              sm_buffer_end(k->fmt) - (space_iter + 1));
    ++ctx->num_delimited;
  }

  // Sort every registered token by length, so longest first. This ensures we
  // get the maximal valid token.
  uint32_t tmp_kind;
  sm_buffer tmp_buf;
  size_t swap_idx; // Move element at swap_idx to the current iterator.

  // First do the literals.
  for (size_t i = 0; i < ctx->num_literal; ++i) {
    // Find the maximum element in this part of the subarray.
    size_t buflen = sm_buffer_length(ctx->literal_spellings[i]);
    tmp_kind = ctx->literal_kinds[i];
    tmp_buf = ctx->literal_spellings[i];
    swap_idx = i;
    for (size_t j = i + 1; j < ctx->num_literal; ++j) {
      if (buflen < sm_buffer_length(ctx->literal_spellings[j])) {
        buflen = sm_buffer_length(ctx->literal_spellings[j]);
        tmp_kind = ctx->literal_kinds[j];
        tmp_buf = ctx->literal_spellings[j];
        swap_idx = j;
      }
    }
    // Place it at the current iterator.
    if (swap_idx != i) {
      ctx->literal_kinds[swap_idx] = ctx->literal_kinds[i];
      ctx->literal_spellings[swap_idx] = ctx->literal_spellings[i];
      ctx->literal_kinds[i] = tmp_kind;
      ctx->literal_spellings[i] = tmp_buf;
    }
  }

  // Now do the delimiters.
  sm_token_chars tmp_open, tmp_close;
  for (size_t i = 0; i < ctx->num_delimited; ++i) {
    // Find the maximum element in this part of the subarray. This means the
    // longest opening delimiter.
    size_t buflen = strlen((const char *)ctx->delimiter_open[i]);
    tmp_kind = ctx->delimited_kinds[i];
    memcpy(tmp_open, ctx->delimiter_open[i], 4);
    memcpy(tmp_close, ctx->delimiter_close[i], 4);
    swap_idx = i;
    for (size_t j = i + 1; j < ctx->num_delimited; ++j) {
      if (buflen < strlen((const char *)ctx->delimiter_open[j])) {
        buflen = strlen((const char *)ctx->delimiter_open[j]);
        tmp_kind = ctx->delimited_kinds[j];
        memcpy(tmp_open, ctx->delimiter_open[j], 4);
        memcpy(tmp_close, ctx->delimiter_close[j], 4);
        swap_idx = j;
      }
    }
    // Place it at the current iterator.
    if (swap_idx != i) {
      // Put the thing at the current spot at the swap_idx.
      memcpy(ctx->delimiter_open[swap_idx], ctx->delimiter_open[i], 4);
      memcpy(ctx->delimiter_close[swap_idx], ctx->delimiter_close[i], 4);
      ctx->delimited_kinds[swap_idx] = ctx->delimited_kinds[i];

      // Put the thing at the swap_idx at the front.
      memcpy(ctx->delimiter_open[i], tmp_open, 4);
      memcpy(ctx->delimiter_close[i], tmp_close, 4);
      ctx->delimited_kinds[i] = tmp_kind;
    }
  }
}

static int get_next_char(sm_lexer_context *ctx) {
  uint8_t currentChar = *ctx->current_ptr++;
  switch (currentChar) {
  default:
    return currentChar;
  case 0: {
    // Disambiguate between EOF and just a normal null character
    if (ctx->current_ptr - 1 != sm_buffer_end(ctx->current_buffer)) {
      return 0;
    }
    --ctx->current_ptr;
    return -1;
  }
  case '\n': // fallthrough
  case '\r': {
    // Skip newlines on unix and DOS platforms (with \r\n or \n\r).
    if ((*ctx->current_ptr == '\n' || (*ctx->current_ptr == '\r')) &&
        *ctx->current_ptr != currentChar) {
      ++ctx->current_ptr;
    }
    return '\n';
  }
  }
}

static sm_token emit_error(sm_lexer_context *ctx, sm_location loc,
                           const sm_buffer msg) {
  sm_diagnostic_engine_emit_error(ctx->diag, loc, msg);
  return (sm_token){.kind = SM_TOKEN_KIND_INVALID, .spelling = sm_empty_buffer};
}

sm_token sm_lexer_lex(sm_lexer_context *ctx) {
  SM_ASSERT(ctx->current_ptr != NULL &&
            sm_buffer_length(ctx->current_buffer) != 0);
  const uint8_t *token_start = ctx->current_ptr;
  int current_char = get_next_char(ctx);
  // We got EOF.
  if (current_char == -1) {
    return (sm_token){SM_TOKEN_KIND_EOF, sm_empty_buffer};
  }

  // Ignore whitespace.
  if (current_char == 0 || current_char == ' ' || current_char == '\r' ||
      current_char == '\n') {
    return sm_lexer_lex(ctx);
  }

  for (size_t i = 0; i < ctx->num_delimited; ++i) {
    // These delimiters are too long for the number of tokens in the buffer.
    if (sm_buffer_end(ctx->current_buffer) - token_start <
        strlen((const char *)ctx->delimiter_open[i]) +
            strlen((const char *)ctx->delimiter_close[i])) {
      continue;
    }

    const sm_buffer token_alias = sm_buffer_alias(
        (uint8_t *)token_start, strlen((const char *)ctx->delimiter_open[i]));
    const sm_buffer open_alias =
        sm_buffer_alias_str((const char *)ctx->delimiter_open[i]);
    if (!sm_buffer_has_prefix(token_alias, open_alias)) {
      continue;
    }
    ctx->current_ptr += strlen((const char *)ctx->delimiter_open[i]) - 1;

    // So at this point, we're at the first char of the delimiter. If the
    // full current pointer alias is the delimiter, then return the token.
    sm_buffer current_ptr_alias =
        sm_buffer_alias_str((const char *)ctx->current_ptr);
    const sm_buffer close_alias =
        sm_buffer_alias_str((const char *)ctx->delimiter_close[i]);
    while (!sm_buffer_has_prefix(current_ptr_alias, close_alias)) {
      ++ctx->current_ptr;
      current_ptr_alias = sm_buffer_alias_str((const char *)ctx->current_ptr);
    }
    // Increment the current ptr by the length of the close alias.
    ctx->current_ptr += sm_buffer_length(close_alias);

    const sm_buffer spelling =
        sm_buffer_alias((uint8_t *)token_start, ctx->current_ptr - token_start);
    return (sm_token){ctx->delimited_kinds[i], spelling};
  }

  for (size_t i = 0; i < ctx->num_literal; ++i) {
    // This literal is too long for the number of tokens in the buffer.
    if (sm_buffer_end(ctx->current_buffer) - token_start <
        sm_buffer_length(ctx->literal_spellings[i])) {
      continue;
    }

    const sm_buffer token_alias = sm_buffer_alias(
        (uint8_t *)token_start, ctx->literal_spellings[i].length);
    if (sm_buffer_equal(ctx->literal_spellings[i], token_alias) &&
        ctx->literal_spellings[i].length != 0) {
      ctx->current_ptr += sm_buffer_length(token_alias) - 1;
      return (sm_token){ctx->literal_kinds[i], token_alias};
    }
  }

  // Now attempt to parse literals.

  // Consume tokens until the next whitespace.
  while (isalnum(*ctx->current_ptr) || *ctx->current_ptr == '_' ||
         *ctx->current_ptr == '.' || *ctx->current_ptr == '-') {
    ++ctx->current_ptr;
  }
  const sm_buffer token_alias =
      sm_buffer_alias((uint8_t *)token_start, ctx->current_ptr - token_start);

  uint8_t *saveptr;

  // For integers, detect the base.
  (void)strtol(sm_buffer_as_str(token_alias), (char **)&saveptr, 0);
  if (saveptr == sm_buffer_end(token_alias)) {
    return (sm_token){SM_TOKEN_KIND_LITERAL, token_alias};
  }

  // Then try float.
  (void)strtod(sm_buffer_as_str(token_alias), (char **)&saveptr);
  if (saveptr == sm_buffer_end(token_alias)) {
    return (sm_token){SM_TOKEN_KIND_LITERAL, token_alias};
  }

  // Finally, string.
  bool is_string = true;
  for (uint8_t *iter = sm_buffer_begin(token_alias),
               *end = sm_buffer_end(token_alias);
       iter != end; ++iter) {
    is_string &= isalnum(*iter) || *iter == '_';
  }
  if (is_string) {
    return (sm_token){SM_TOKEN_KIND_LITERAL, token_alias};
  }

  return emit_error(
      ctx, (sm_location){token_start},
      sm_buffer_alias_str("character did not have a defined token.\n"));
}
