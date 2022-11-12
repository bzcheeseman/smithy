//
// Copyright 2022 Aman LaChapelle
// Full license at auth/LICENSE.txt
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

#include <stdbool.h>
#include <stdint.h>

#include <jansson.h>

#include "smithy/crypto/sign_engine.h"
#include "smithy/crypto/verify_engine.h"

/// Smithy token representation. It outlines a standard JWT. On construction,
/// the header is filled in with some default values, and the payload is left
/// empty.
///
/// This structure should be treated as opaque.
typedef struct {
  sm_sign_algorithm alg;
  json_t *header;
  json_t *payload;
} sm_token;

/// Initialize a `sm_token` with a given signing algorithm. This will correctly
/// set up the header with the `typ` and `alg` fields.
void sm_token_init(sm_sign_algorithm alg, sm_token *token);
/// Free a given token.
void sm_token_cleanup(sm_token *token);

/// Needed for SM_AUTO macro.
static inline void free_sm_token(sm_token *tokenp) {
  if (tokenp) {
    sm_token_cleanup(tokenp);
  }
}

/// Debug print a token.
void sm_token_print(sm_token *token);

/// Add a header to the token. The value can be any byte string representable
/// with an sm_buffer (which is anything you can take the address of).
void sm_token_add_header(sm_token *token, char *hdr, const sm_buffer value);
/// Add a string header.
void sm_token_add_string_header(sm_token *token, char *hdr, char *value);

/// Add claims to the token. These functions set the {"claim": <value>}
/// dictionary as a field in the payload of `token`.
void sm_token_add_claim(sm_token *token, char *claim, const sm_buffer value);
void sm_token_add_string_claim(sm_token *token, char *claim, const char *value);
void sm_token_add_int_claim(sm_token *token, char *claim, int64_t value);

/// Get a claim from `token` by name.
bool sm_token_get_claim(sm_token *token, char *claim, sm_buffer *value);

/// Serialize and deserialize a token. This will sign (serialize) and verify
/// (deserialize) the signature on the token.
bool sm_token_serialize(const sm_token *token, sm_sign_ctx *engine,
                        sm_buffer *serialized);
bool sm_token_deserialize(sm_token *token, sm_verify_ctx *engine,
                          const sm_certificate_chain *chain,
                          const sm_buffer serialized);
