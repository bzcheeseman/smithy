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

#include "smithy/authn/jwt.h"
#include "smithy/json/json.h"
#include "smithy/stdlib/alloc.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/b64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *print_algorithm(sm_sign_algorithm alg) {
  switch (alg) {
  case RS256: {
    return "RS256";
  }
  case ES256: {
    return "ES256";
  }
  default: {
    return NULL;
  }
  }
}

static sm_sign_algorithm parse_algorithm(const char *alg) {
  if (strncmp(alg, "RS256", 5) == 0) {
    return RS256;
  } else if (strncmp(alg, "ES256", 5) == 0) {
    return ES256;
  }

  return UNKNOWN;
}

void sm_token_init(sm_sign_algorithm alg, sm_token *token) {
  json_set_alloc_funcs(sm_malloc, sm_free);

  token->alg = alg;

  // Build the header
  token->header = json_object();
  json_auto_t *jwt = json_string("JWT");
  SM_ASSERT(json_object_set(token->header, "typ", jwt) >= 0);
  json_auto_t *algorithm = json_string(print_algorithm(token->alg));
  SM_ASSERT(json_object_set(token->header, "alg", algorithm) >= 0);

  // Build the payload
  token->payload = json_object();
}

void sm_token_cleanup(sm_token *token) {
  if (!token) {
    return;
  }

  json_decref(token->header);
  json_decref(token->payload);
}

void sm_token_print(sm_token *token) {
  char *hdr = json_dumps(token->header, JSON_SORT_KEYS);
  char *payload = json_dumps(token->payload, JSON_SORT_KEYS);
  printf("Header: %s\nPayload: %s\n", hdr, payload);
  sm_free(hdr);
  sm_free(payload);
}

void sm_token_add_header(sm_token *token, char *hdr, const sm_buffer value) {
  json_auto_t *val = json_buffer(value);
  json_object_set(token->header, hdr, val);
}

void sm_token_add_string_header(sm_token *token, char *hdr, char *value) {
  json_auto_t *val = json_string(value);
  json_object_set(token->header, hdr, val);
}

void sm_token_add_claim(sm_token *token, char *claim, const sm_buffer value) {
  json_auto_t *val = json_buffer(value);
  json_object_set(token->payload, claim, val);
}

void sm_token_add_string_claim(sm_token *token, char *claim,
                               const char *value) {
  json_auto_t *val = json_string(value);
  json_object_set(token->payload, claim, val);
}

void sm_token_add_int_claim(sm_token *token, char *claim, int64_t value) {
  json_auto_t *val = json_integer(value);
  json_object_set(token->payload, claim, val);
}

bool sm_token_get_claim(sm_token *token, char *claim, sm_buffer *value) {
  json_t *c = json_object_get(token->payload, claim);
  if (!c) {
    return false;
  }

  const char *v = json_string_value(c);
  sm_buffer_insert(value, sm_buffer_begin(*value), (const uint8_t *)(v),
                   (const uint8_t *)(v + strlen(v)));
  return true;
}

bool sm_token_serialize(const sm_token *token, sm_sign_ctx *engine,
                        sm_buffer *serialized) {

  char *hdr = json_dumps(token->header, JSON_COMPACT);
  const SM_AUTO(sm_buffer) json_hdr = sm_buffer_alias_str(hdr);

  SM_AUTO(sm_buffer) ser_hdr = sm_empty_buffer;
  SM_ASSERT(sm_b64_encode(SM_B64_URL_ENCODING_NOPAD, json_hdr, &ser_hdr));

  char *payload = json_dumps(token->payload, JSON_COMPACT);
  const SM_AUTO(sm_buffer) json_payload = sm_buffer_alias_str(payload);

  SM_AUTO(sm_buffer) ser_payload = sm_empty_buffer;
  SM_ASSERT(
      sm_b64_encode(SM_B64_URL_ENCODING_NOPAD, json_payload, &ser_payload));

  SM_AUTO(sm_buffer) to_sign = sm_empty_buffer;
  // Add the header
  sm_buffer_insert(&to_sign, sm_buffer_end(to_sign), sm_buffer_begin(ser_hdr),
                   sm_buffer_end(ser_hdr));
  // Add the '.'
  sm_buffer_push(&to_sign, '.');
  // Add the payload
  sm_buffer_insert(&to_sign, sm_buffer_end(to_sign),
                   sm_buffer_begin(ser_payload), sm_buffer_end(ser_payload));

  SM_AUTO(sm_buffer) signature = sm_empty_buffer;
  SM_ASSERT(sm_sign_engine_sign(engine, to_sign, &signature));

  SM_AUTO(sm_buffer) b64_signature = sm_empty_buffer;
  SM_ASSERT(
      sm_b64_encode(SM_B64_URL_ENCODING_NOPAD, signature, &b64_signature));

  // string.string.string
  sm_buffer_reserve(serialized, sm_buffer_length(ser_hdr) + 1 +
                                    sm_buffer_length(ser_payload) + 1 +
                                    sm_buffer_length(b64_signature));

  // Add header
  sm_buffer_insert(serialized, sm_buffer_end(*serialized),
                   sm_buffer_begin(ser_hdr), sm_buffer_end(ser_hdr));
  // Add '.'
  sm_buffer_push(serialized, '.');
  // Add payload
  sm_buffer_insert(serialized, sm_buffer_end(*serialized),
                   sm_buffer_begin(ser_payload), sm_buffer_end(ser_payload));
  // Add '.'
  sm_buffer_push(serialized, '.');
  // Add signature
  sm_buffer_insert(serialized, sm_buffer_end(*serialized),
                   sm_buffer_begin(b64_signature),
                   sm_buffer_end(b64_signature));

  return true;
}

bool sm_token_deserialize(sm_token *token, sm_verify_ctx *engine,
                          const sm_certificate_chain *chain,
                          const sm_buffer serialized) {
  // Parse the header, payload, signature
  uint8_t *b64_header_unpadded = sm_buffer_begin(serialized);
  uint8_t *b64_payload_unpadded = sm_buffer_begin(serialized);
  uint8_t *b64_signature_unpadded = sm_buffer_begin(serialized);

  // Since we always start with the header, we increment the payload and the
  // signature until we find the first '.'
  while (*b64_payload_unpadded++ != '.') {
    ++b64_signature_unpadded;
  }
  // One more to get us past the '.'
  ++b64_signature_unpadded;

  // Then do the same for the signature
  while (*b64_signature_unpadded++ != '.') {
  }

  // Then the end ptr is the end of the the serialized buffer

  // Create the serialized header buf
  size_t hdr_len = (b64_payload_unpadded - 1) - b64_header_unpadded;
  sm_buffer ser_hdr_buf = sm_buffer_alias(b64_header_unpadded, hdr_len);

  // Create the serialized payload buf
  size_t payload_len = (b64_signature_unpadded - 1) - b64_payload_unpadded;
  sm_buffer ser_payload_buf =
      sm_buffer_alias(b64_payload_unpadded, payload_len);

  // Create the buffer that we need to compute the signature over
  sm_buffer to_sign =
      sm_buffer_alias(b64_header_unpadded, hdr_len + 1 + payload_len);

  // Now parse the buffers
  // Pad it out and parse it
  SM_AUTO(sm_buffer) hdr_buf = sm_empty_buffer;
  if (!sm_b64_decode(SM_B64_URL_ENCODING_NOPAD, ser_hdr_buf, &hdr_buf)) {
    SM_ERROR("Header decoding failed\n");
    return false;
  }

  SM_ASSERT(sm_buffer_begin(hdr_buf));
  json_error_t err;
  token->header = json_loadb((const char *)sm_buffer_begin(hdr_buf),
                             sm_buffer_length(hdr_buf), 0, &err);
  if (!token->header) {
    SM_ERROR("JSON decoding error: %s", err.text);
    return false;
  }

  // Handle the header
  json_t *alg_json = json_object_get(token->header, "alg");
  const char *alg = json_string_value(alg_json);
  token->alg = parse_algorithm(alg);
  SM_ASSERT(token->alg != UNKNOWN);

  // Pad it out and parse it
  SM_AUTO(sm_buffer) payload_buf = sm_empty_buffer;
  if (!sm_b64_decode(SM_B64_URL_ENCODING_NOPAD, ser_payload_buf,
                     &payload_buf)) {
    SM_ERROR("Payload decoding failed\n");
    return false;
  }

  SM_ASSERT(sm_buffer_begin(payload_buf));
  memset(&err, 0, sizeof(err));
  token->payload = json_loadb((const char *)sm_buffer_begin(payload_buf),
                              sm_buffer_length(payload_buf), 0, &err);
  if (!token->payload) {
    SM_ERROR("JSON decoding error: %s", err.text);
    return false;
  }

  // Create the signature buffer
  size_t sig_len = sm_buffer_end(serialized) - b64_signature_unpadded;
  sm_buffer ser_sig_buf = sm_buffer_alias(b64_signature_unpadded, sig_len);

  // Decode the signature
  SM_AUTO(sm_buffer) sig_buf = sm_empty_buffer;
  if (!sm_b64_decode(SM_B64_URL_ENCODING_NOPAD, ser_sig_buf, &sig_buf)) {
    SM_ERROR("Signature decoding failed\n");
    return false;
  }
  SM_ASSERT(sm_buffer_begin(sig_buf));

  // Verify the signature
  if (!sm_verify_engine_verify(engine, to_sign, sig_buf, chain)) {
    SM_ERROR("Signature verification failed\n");
    return false;
  }

  return true;
}
