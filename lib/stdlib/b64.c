/*
 * Constant-time b64 encode/decode implementation adapted from libsodium source.
 * libsodium is distributed under the ISC license:
 *
 * ISC License
 *
 * Copyright (c) 2013-2021
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <memory.h>
#include <stdlib.h>

#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/b64.h"

/*
 * Some macros for constant-time comparisons. These work over values in
 * the 0..255 range. Returned value is 0x00 on "false", 0xFF on "true".
 *
 * Original code by Thomas Pornin.
 */
#define EQ(x, y)                                                               \
  ((((0u - ((unsigned int)(x) ^ (unsigned int)(y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned int)(y) - (unsigned int)(x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)
#define LE(x, y) GE(y, x)

static int b64_byte_to_char(unsigned int x) {
  return (LT(x, 26) & (x + 'A')) | (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
         (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '+') |
         (EQ(x, 63) & '/');
}

static unsigned int b64_char_to_byte(int c) {
  const unsigned int x = (GE(c, 'A') & LE(c, 'Z') & (c - 'A')) |
                         (GE(c, 'a') & LE(c, 'z') & (c - ('a' - 26))) |
                         (GE(c, '0') & LE(c, '9') & (c - ('0' - 52))) |
                         (EQ(c, '+') & 62) | (EQ(c, '/') & 63);

  return x | (EQ(x, 0) & (EQ(c, 'A') ^ 0xFF));
}

static int b64_byte_to_urlsafe_char(unsigned int x) {
  return (LT(x, 26) & (x + 'A')) | (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
         (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '-') |
         (EQ(x, 63) & '_');
}

static unsigned int b64_urlsafe_char_to_byte(int c) {
  const unsigned x = (GE(c, 'A') & LE(c, 'Z') & (c - 'A')) |
                     (GE(c, 'a') & LE(c, 'z') & (c - ('a' - 26))) |
                     (GE(c, '0') & LE(c, '9') & (c - ('0' - 52))) |
                     (EQ(c, '-') & 62) | (EQ(c, '_') & 63);

  return x | (EQ(x, 0) & (EQ(c, 'A') ^ 0xFF));
}

#define NO_PADDING_MASK 0x2
#define URLSAFE_MASK 0x1

bool sm_b64_encode(sm_b64_encoding enc, const sm_buffer s, sm_buffer *d) {
  SM_ASSERT(enc < SM_B64_ENCODING_END);
  size_t len = sm_buffer_length(s);
  uint8_t *src = sm_buffer_begin(s);

  size_t nibbles = len / 3;
  size_t remainder = len - 3 * nibbles;
  size_t b64_len = nibbles * 4;
  if (remainder != 0) {
    if ((((unsigned int)enc) & NO_PADDING_MASK) == 0u) {
      b64_len += 4;
    } else {
      b64_len += 2 + (remainder >> 1);
    }
  }

  // Resize the buffer
  sm_buffer_resize(d, b64_len);
  uint8_t *dst = sm_buffer_begin(*d);
  if (dst == NULL) {
    return false;
  }

  // Do the encoding
  uint32_t acc = 0u;
  size_t acc_len = 0;
  int (*byte_to_char)(unsigned) = NULL;
  if ((((unsigned int)enc) & URLSAFE_MASK) == 0u) {
    byte_to_char = b64_byte_to_char;
  } else if ((((unsigned int)enc) & URLSAFE_MASK) == 1u) {
    byte_to_char = b64_byte_to_urlsafe_char;
  }
  SM_ASSERT(byte_to_char != NULL);
  while (src != sm_buffer_end(s)) {
    acc = (acc << 8) + *(src++);
    acc_len += 8;
    while (acc_len >= 6) {
      acc_len -= 6;
      *dst++ = (char)byte_to_char((acc >> acc_len) & 0x3F);
    }
  }
  if (acc_len > 0) {
    *dst++ = (char)byte_to_char((acc << (6 - acc_len)) & 0x3F);
  }

  SM_ASSERT(dst <= sm_buffer_end(*d));
  while (dst != sm_buffer_end(*d)) {
    *dst++ = '=';
  }
  return true;
}

bool sm_b64_decode(sm_b64_encoding enc, const sm_buffer s, sm_buffer *d) {
  SM_ASSERT(enc < SM_B64_ENCODING_END);
  size_t len = sm_buffer_length(s);
  uint8_t *src = sm_buffer_begin(s);

  // Always divisible by 4
  size_t nibbles = len / 4;
  size_t remainder = len - 4 * nibbles;
  size_t bin_len = nibbles * 3;
  if (remainder != 0) {
    if ((((unsigned int)enc) & NO_PADDING_MASK) == 0u) {
      bin_len += 3;
    } else {
      bin_len += 1 + (remainder >> 1);
    }
  }

  sm_buffer_resize(d, bin_len);
  uint8_t *dst = sm_buffer_begin(*d);
  if (dst == NULL) {
    SM_DEBUG("sm_buffer_begin returned NULL for destination\n");
    return false;
  }

  // Do the decoding
  uint32_t acc = 0u;
  size_t acc_len = 0;
  bool ret = true;

  // Choose the correct decoder function pointer here
  unsigned (*char_to_byte)(int) = NULL;
  if ((((unsigned int)enc) & URLSAFE_MASK) == 1u) {
    char_to_byte = b64_urlsafe_char_to_byte;
  } else if ((((unsigned int)enc) & URLSAFE_MASK) == 0u) {
    char_to_byte = b64_char_to_byte;
  }
  SM_ASSERT(char_to_byte != NULL);

  // Do the actual decoding
  while (src != sm_buffer_end(s)) {
    uint8_t b = char_to_byte(*src);
    if (b == 0xff) {
      break;
    }

    acc = (acc << 6) + b;
    acc_len += 6;
    if (acc_len >= 8) {
      acc_len -= 8;
      if (dst >= sm_buffer_end(*d)) {
        ret = false;
        SM_DEBUG("dst_ptr >= sm_buffer_end\n");
        break;
      }
      *dst++ = (acc >> acc_len) & 0xff;
    }
    ++src;
  }

  // Cleanup the end
  if (acc_len > 4u || (acc & ((1u << acc_len) - 1u)) != 0u) {
    SM_DEBUG("acc_len\n");
    ret = false;
  } else if (ret == true && (((unsigned int)enc) & NO_PADDING_MASK) == 0u) {
    size_t padding_len = acc_len / 2;
    while (padding_len > 0) {
      if (src >= sm_buffer_end(s)) {
        SM_DEBUG("src >= buffer_end\n");
        ret = false;
      }
      char c = *src++;
      if (c == '=') {
        padding_len--;
      }
    }
  }
  if (src != sm_buffer_end(s)) {
    SM_DEBUG("src != buffer_end\n");
    ret = false;
  }
  size_t actual_len = dst - sm_buffer_begin(*d);
  sm_buffer_resize(d, actual_len);
  return ret;
}
