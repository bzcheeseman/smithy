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

#include "smithy/crypto/stream.h"

void sm_stream_ctx_init(sm_stream_ctx *ctx, sm_symmetric_key key,
                        sm_buffer *iv) {
  ctx->counter = 0;
  ctx->key = key;

  // If an IV was provided, use it. The context takes ownership of the IV.
  if (iv) {
    ctx->iv = sm_buffer_clone(*iv);
    return;
  }

  // Initialize the IV with a random number.
  ctx->iv = sm_empty_buffer;
  sm_buffer_resize(&ctx->iv, 12);
  sm_buffer_fill_rand(ctx->iv, sm_buffer_begin(ctx->iv),
                      sm_buffer_end(ctx->iv));
}

void sm_stream_ctx_cleanup(sm_stream_ctx *ctx) { sm_buffer_cleanup(ctx->iv); }

static void stream_update(sm_stream_ctx *ctx, const sm_buffer data) {
  switch (ctx->key.algorithm) {
  case SM_AES_128_GCM: // fallthrough
  case SM_AES_192_GCM: // fallthrough
  case SM_AES_256_GCM: // fallthrough
    ctx->counter = br_aes_ct64_ctr_run(
        &ctx->key.k.aes, sm_buffer_begin(ctx->iv), ctx->counter,
        sm_buffer_begin(data), sm_buffer_length(data));
    break;
  case SM_CHACHA20_POLY1305:
    ctx->counter = br_chacha20_ct_run(
        ctx->key.k.chacha, sm_buffer_begin(ctx->iv), ctx->counter,
        sm_buffer_begin(data), sm_buffer_length(data));
    break;
  }
}

void sm_stream_encrypt(sm_stream_ctx *ctx, sm_buffer data) {
  stream_update(ctx, data);
}

static size_t get_encryption_blocksize(sm_stream_ctx *ctx) {
  switch (ctx->key.algorithm) {
  case SM_AES_128_GCM: // fallthrough
  case SM_AES_192_GCM: // fallthrough
  case SM_AES_256_GCM:
    return br_aes_ct_BLOCK_SIZE;
  case SM_CHACHA20_POLY1305:
    return 64;
  }
}

static void set_counter_position(sm_stream_ctx *ctx, size_t bytepos) {
  // The block that contains byte `bytepos` is the floor division of that
  // position with 64. C integer division is always a floor - it's truncated
  // towards zero.
  size_t blockno = bytepos / get_encryption_blocksize(ctx);
  ctx->counter = blockno;
}

bool sm_stream_decrypt(sm_stream_ctx *ctx, sm_buffer data,
                       size_t begin_offset) {
  // The offset from the beginning of the stream gives us the counter position
  // we need.
  set_counter_position(ctx, begin_offset);

  uint8_t *begin = sm_buffer_begin(data);

  // Align the beginning to the nearest block boundary. You have to start from
  // the beginning of a block even if you don't end at the end of a block.
  size_t beginpos = ctx->counter * get_encryption_blocksize(ctx);
  if (begin_offset > beginpos)
    begin -= (begin_offset - beginpos);

  // The length is the distance between the end and this new beginning position.
  intptr_t len = sm_buffer_end(data) - begin;
  if (len < 0) {
    SM_ERROR("`end` cannot be before `begin`\n");
    return false;
  }

  sm_buffer alias = sm_buffer_alias(begin, len);
  // This will update the bytes in-place.
  stream_update(ctx, alias);
  return true;
}
