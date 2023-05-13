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

#include "smithy/crypto/symmetric_key.h"
#include "smithy/stdlib/buffer.h"

#include <bearssl.h>

/// The context for stream encryption. This struct shall be regarded as opaque.
typedef struct {
  uint32_t counter;
  sm_symmetric_key key;
  sm_buffer iv;
} sm_stream_ctx;

/// Initialize a stream context with the provided key bytes. This initializes
/// the counter to 0 - it assumes that the context will be used for an entire
/// stream. If the IV is provided, it copies the bytes into its internal
/// context, otherwise it initializes the IV randomly using the system CSPRNG.
///
/// Note that this is unauthenticated encryption because GCM/POLY1305 are
/// authentication tags computed over the entire cipher stream. If you want
/// authenticated encryption, you should either layer a signature over this or
/// use the sm_symmetric_* APIs.
void sm_stream_ctx_init(sm_stream_ctx *ctx, sm_symmetric_key key,
                        sm_buffer *iv);

/// Clean up the stream context. This will free the data in the
/// randomly-initialized IV.
void sm_stream_ctx_cleanup(sm_stream_ctx *ctx);

/// Needed for SM_AUTO macro
static inline void free_sm_stream_ctx(const sm_stream_ctx *ctx) {
  if (ctx) {
    sm_stream_ctx_cleanup((sm_stream_ctx *)ctx);
  }
}

/// Encrypt `data` in-place. Provide an sm_buffer of data to be encrypted whose
/// underlying data will be encrypted in-place.
void sm_stream_encrypt(sm_stream_ctx *ctx, sm_buffer data);

/// Decrypt a part of a buffer. Provide a buffer (that may alias into another
/// buffer) along with the offset in bytes from the beginning of the cipher
/// stream. The stream decryption must start on a block boundary, therefore this
/// API will read data starting from:
///
///   sm_buffer_begin(data) - (trunc(begin_offset / blocksize)) * blocksize
///
/// This means that the caller MUST ensure that `data` is a valid alias of the
/// actual cipher stream.
bool sm_stream_decrypt(sm_stream_ctx *ctx, sm_buffer data, size_t begin_offset);
