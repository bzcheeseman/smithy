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

typedef struct {
  sm_sign_algorithm alg;
  json_t *header;
  json_t *payload;
} sm_token;

void init_token(sm_sign_algorithm alg, sm_token *token);
void free_token(sm_token *token);

/// Needed for SM_AUTO macro
static inline void free_sm_token(sm_token *tokenp) {
  if (tokenp) {
    free_token(tokenp);
  }
}

void sm_token_print(sm_token *token);

// Adding headers to the JSON token
void sm_token_add_header(sm_token *token, char *hdr, const sm_buffer value);
void sm_token_add_string_header(sm_token *token, char *hdr, char *value);

// Adding claims to the JSON token
void sm_token_add_claim(sm_token *token, char *claim, const sm_buffer value);
void sm_token_add_string_claim(sm_token *token, char *claim, const char *value);
void sm_token_add_int_claim(sm_token *token, char *claim, int64_t value);

// Getting claims from the JSON token
bool sm_token_get_claim(sm_token *token, char *claim, sm_buffer *value);

// Serialization and deserialization. Serialize signs and deserialize verifies
// the signature.
bool sm_token_serialize(const sm_token *token, sm_sign_ctx *engine,
                     sm_buffer *serialized);
bool sm_token_deserialize(sm_token *token, sm_verify_ctx *engine,
                       const sm_certificate_chain *chain,
                       const sm_buffer serialized);
