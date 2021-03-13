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

#include "smithy/parser/diagnostic_engine.h"
#include "smithy/stdlib/buffer.h"

#define SM_TOKEN_KIND_EOF UINT32_MAX
#define SM_TOKEN_KIND_INVALID 0
#define SM_TOKEN_KIND_LITERAL 1
#define SM_TOKEN_KIND_USER_START 2

#define SM_TOKEN_IS_LITERAL(tok) ((tok).kind == SM_TOKEN_KIND_LITERAL)

typedef struct {
  // There are 2 special tokens - 0 means invalid token, UINT32_MAX means EOF.
  uint32_t kind;
  sm_buffer spelling;
} sm_token;

typedef struct {
  uint32_t kind;
  // For a keyword or literal like `let` this would contain "let". For a
  // delimited token like a string, this would contain "[{ }]". For a token like
  // a C-style single line comment, this would contain "// \n". The space is
  // important because it indicates that there should be something there. For
  // all delimited tokens, the delimiters are included in the token's spelling
  // and the parser is responsible for removing them as appropriate.
  sm_buffer fmt;
} sm_token_kind;

// Many of these things need very short strings - allocate 4 chars for things
// like prefixes, delimiters, formats.
typedef uint8_t sm_token_chars[4];
static const size_t sm_token_char_size = 4;

// All the lists of buffers here are alias buffers, so they shouldn't be freed!
// The user manages that memory.
typedef struct {
  uint32_t *literal_kinds;
  sm_buffer *literal_spellings;
  size_t num_literal;

  uint32_t *delimited_kinds;
  // Delimiter open/close can be at most 4 chars.
  sm_token_chars *delimiter_open;
  sm_token_chars *delimiter_close;
  size_t num_delimited;

  // NOTE: does not own this buffer!
  sm_buffer current_buffer;
  uint8_t *current_ptr;

  sm_diagnostic_engine_context *diag;
} sm_lexer_context;

void sm_lexer_cleanup(sm_lexer_context *ctx);

// Needed for SM_AUTO.
static inline void free_sm_lexer_context(sm_lexer_context *ctx) {
  sm_lexer_cleanup(ctx);
}

void sm_lexer_set_buffer(sm_lexer_context *ctx, const sm_buffer buffer);

void sm_lexer_register_tokens(sm_lexer_context *ctx, const sm_token_kind *kinds,
                              size_t num_kinds);

sm_token sm_lexer_lex(sm_lexer_context *ctx);
