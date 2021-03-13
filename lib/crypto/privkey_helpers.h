//
// Copyright 2022 Aman LaChapelle
// Full license at keyderiver/LICENSE.txt
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

#include "smithy/crypto/sign_engine.h"
#include "smithy/stdlib/logging.h"

#include <bearssl.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

static inline void skey_decoder(void *ctx, const void *data, size_t data_len) {
  br_skey_decoder_push(ctx, data, data_len);
}

static inline void sm_load_privkey(const sm_buffer key,
                                   br_skey_decoder_context *decoder_ctx) {

  br_pem_decoder_context ctx;
  br_pem_decoder_init(&ctx);

  // Copy the data into the signing key
  br_pem_decoder_setdest(&ctx, &skey_decoder, decoder_ctx);

  // Decode the pem object
  size_t decoded =
      br_pem_decoder_push(&ctx, sm_buffer_begin(key), sm_buffer_length(key));
  uint8_t *keyptr = sm_buffer_begin(key) + decoded;
  size_t len = sm_buffer_length(key) - decoded;
  while (decoded < sm_buffer_length(key)) {
    int event = br_pem_decoder_event(&ctx);
    // If the event is the end of the object, then break the loop
    if (event == BR_PEM_END_OBJ) {
      break;
    } else if (event == BR_PEM_ERROR) {
      SM_FATAL("PEM decoding failed\n");
      break;
    }
    size_t d = br_pem_decoder_push(&ctx, keyptr, len);
    keyptr += d;
    len -= d;
    decoded += d;
  }
}
