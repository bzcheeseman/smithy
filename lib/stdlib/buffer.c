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

#include "smithy/stdlib/buffer.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/memory.h"

#include <stdio.h>

#ifdef SM_NEEDS_BSD
#include <bsd/stdlib.h>
#endif

#ifndef SM_RANDOM_BUF
#error "Must define SM_RANDOM_BUF"
#endif

static void buffer_grow_(sm_buffer *buf, size_t newsize) {
  SM_ASSERT(buf);
  // Don't need to grow the buffer
  if (newsize <= buf->capacity) {
    return;
  }

  void *tmp = sm_realloc(buf->data, newsize);
  SM_ASSERT(tmp);
  buf->data = tmp;
  buf->capacity = newsize;
}

void sm_buffer_push(sm_buffer *buf, uint8_t elt) {
  // Request the grow, knowing that it won't happen if the capacity is large
  // enough
  buffer_grow_(buf, buf->length + 1);

  *sm_buffer_end(*buf) = elt;
  ++buf->length;
}

uint8_t sm_buffer_pop(sm_buffer *buf) {
  // Decrement the length so the sm_buffer_end function gives us the right thing
  --buf->length;
  // Get the last element
  const uint8_t out = *sm_buffer_end(*buf);
  // Clean it out
  *sm_buffer_end(*buf) = 0;

  return out;
}

void sm_buffer_insert(sm_buffer *buf, uint8_t *pos, const uint8_t *first,
                      const uint8_t *last) {
  ptrdiff_t added_size = (ptrdiff_t)last - (ptrdiff_t)first;
  // It's an error if first > last
  SM_ASSERT(added_size >= 0);
  // Easy out if first == last
  if (added_size == 0) {
    return;
  }
  // Check what the offset of pos is before we grow anything to save our state
  // for later.
  ptrdiff_t pos_offset = ((ptrdiff_t)pos - (ptrdiff_t)sm_buffer_begin(*buf));

  // Store a flag to check if the buffer is empty before we grow it
  bool is_empty = buf->length == 0 && buf->capacity == 0 && buf->data == NULL;
  if (is_empty) {
    // If the buffer is empty, assert that pos is NULL (i.e. begin or end)
    SM_ASSERT(pos == NULL && pos_offset == 0);
  }

  // The new size is the current length plus any added size in the elements
  size_t newsize = buf->length + added_size;

  // buffer_grow_ will only grow the buffer if it's required
  buffer_grow_(buf, newsize);

  // Because we maybe did a realloc, we have to reset the position pointer
  pos = sm_buffer_begin(*buf) + pos_offset;

  // Grab a pointer to the end *before* we increase the length, but after we
  // grew the buffer (or not, as the case may be)
  const uint8_t *end = sm_buffer_end(*buf);

  // Save the number of bytes we're moving around now because it's easier that
  // way
  const size_t bytes_to_move = buf->length - pos_offset;

  // Increase the length now
  buf->length = newsize;

  // If we're inserting at the end, then just copy the new data in
  if (pos == end) {
    sm_memmove(pos, first, added_size);
    return;
  }

  // Since we insert new data *before* pos, that means that we have to move the
  // old data (from pos to the end) back in the buffer.
  sm_memmove(pos + added_size, pos, bytes_to_move);

  // Then copy in the new data to the spot that was just vacated
  sm_memmove(pos, first, added_size);
}

void sm_buffer_fill_rand(sm_buffer buf, uint8_t *pos, const uint8_t *last) {
  if (last == NULL) {
    last = sm_buffer_end(buf);
  }

  ptrdiff_t added_size = (ptrdiff_t)last - (ptrdiff_t)pos;
  // It's an error if pos > last or if pos - last > buf.length
  SM_ASSERT(added_size >= 0 && added_size <= buf.length);
  // Easy out if pos == last
  if (added_size == 0) {
    return;
  }

  // Fill with the system RNG
  SM_RANDOM_BUF(pos, added_size);
}

void sm_buffer_resize(sm_buffer *buf, size_t newlen) {
  buffer_grow_(buf, newlen);
  buf->length = newlen;
}

void sm_buffer_reserve(sm_buffer *buf, size_t newcap) {
  buffer_grow_(buf, newcap);
}

void sm_buffer_clear(sm_buffer *buf) {
  if (buf->data == NULL) {
    return;
  }

  for (volatile uint8_t *iter = sm_buffer_begin(*buf),
                        *end = sm_buffer_end(*buf);
       iter != end; ++iter) {
    *iter = 0;
  }
  buf->length = 0;
}

bool sm_buffer_equal(sm_buffer lhs, sm_buffer rhs) {
  bool diff = sm_buffer_length(lhs) != sm_buffer_length(rhs);
  uint8_t *lhs_iter = sm_buffer_begin(lhs);
  uint8_t *lhs_end = sm_buffer_end(lhs);
  uint8_t *rhs_iter = sm_buffer_begin(rhs);
  uint8_t *rhs_end = sm_buffer_end(rhs);
  for (; lhs_iter != lhs_end && rhs_iter != rhs_end; ++lhs_iter, ++rhs_iter) {
    diff |= *lhs_iter ^ *rhs_iter;
  }

  return !diff;
}

uint8_t *sm_buffer_find(sm_buffer buf, uint8_t to_find) {
  for (uint8_t *iter = sm_buffer_begin(buf), *end = sm_buffer_end(buf);
       iter != end; ++iter) {
    if (*iter == to_find) {
      return iter;
    }
  }

  return sm_buffer_end(buf);
}

bool sm_buffer_has_prefix(sm_buffer buf, sm_buffer prefix) {
  bool diff = false;
  uint8_t *buf_iter = sm_buffer_begin(buf);
  uint8_t *buf_end = sm_buffer_end(buf);
  uint8_t *prefix_iter = sm_buffer_begin(prefix);
  uint8_t *prefix_end = sm_buffer_end(prefix);
  for (; buf_iter != buf_end && prefix_iter != prefix_end;
       ++buf_iter, ++prefix_iter) {
    diff |= *buf_iter ^ *prefix_iter;
  }
  return !diff;
}

bool sm_buffer_has_suffix(sm_buffer buf, sm_buffer suffix) {
  bool diff = false;
  uint8_t *buf_iter = sm_buffer_end(buf) - sm_buffer_length(suffix);
  uint8_t *buf_end = sm_buffer_end(buf);
  uint8_t *prefix_iter = sm_buffer_begin(suffix);
  uint8_t *prefix_end = sm_buffer_end(suffix);
  for (; buf_iter != buf_end && prefix_iter != prefix_end;
       ++buf_iter, ++prefix_iter) {
    diff |= *buf_iter ^ *prefix_iter;
  }
  return !diff;
}

void sm_buffer_print(sm_buffer *buf, const char *fmt, ...) {
  va_list args1;
  va_start(args1, fmt);
  va_list args2;
  va_copy(args2, args1);

  // get the length
  int buflen = vsnprintf(NULL, 0, fmt, args1);
  va_end(args1);

  // Resize the buffer
  SM_ASSERT(buflen > 0);
  size_t current_len = sm_buffer_length(*buf);
  sm_buffer_reserve(buf, current_len + (size_t)buflen + 1);

  // Do the print into the end of the buffer
  vsnprintf((char *)sm_buffer_end(*buf), buflen + 1, fmt, args2);
  // Resize the buffer (just updates the length, realloc already happened)
  sm_buffer_resize(buf, current_len + buflen + 1);
  // Pop off the last element (null terminator)
  sm_buffer_pop(buf);
  va_end(args2);
}

void sm_buffer_vprint(sm_buffer *buf, const char *fmt, va_list args) {
  va_list copy;
  va_copy(copy, args);

  // get the length
  int buflen = vsnprintf(NULL, 0, fmt, copy);
  va_end(copy);

  // Resize the buffer
  SM_ASSERT(buflen > 0);
  size_t current_len = sm_buffer_length(*buf);
  sm_buffer_reserve(buf, current_len + (size_t)buflen + 1);

  // Do the print into the end of the buffer
  vsnprintf((char *)sm_buffer_end(*buf), buflen + 1, fmt, args);
  // Resize the buffer (just updates the length, realloc already happened)
  sm_buffer_resize(buf, current_len + buflen + 1);
  // Pop off the last element (null terminator)
  sm_buffer_pop(buf);
}
