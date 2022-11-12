//
// Created by Aman LaChapelle on 8/15/18.
//
// smithy
// Copyright (c) 2021 Aman LaChapelle
// Full license at smithy/LICENSE.txt
//

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "smithy/stdlib/buffer.h"

typedef enum {
  SM_B64_STANDARD_ENCODING = 0x0,
  SM_B64_URL_ENCODING = 0x1,
  // high bit set means no padding
  SM_B64_STANDARD_ENCODING_NOPAD = 0x2,
  SM_B64_URL_ENCODING_NOPAD = 0x3,
  // MAX is only for checking validity of the inputs
  SM_B64_ENCODING_END = 0x4,
} sm_b64_encoding;

/// Provides constant-time b64 encoding and decoding. Given an encoding, a
/// source, and destination buffer, either b64 encode or b64 decode `src` and
/// place the result in `dst`. Returns true on success and false on failure.
bool sm_b64_encode(sm_b64_encoding enc, const sm_buffer src, sm_buffer *dst);
bool sm_b64_decode(sm_b64_encoding enc, const sm_buffer src, sm_buffer *dst);
