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

#include "smithy/stdlib/alloc.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/memory.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef SM_STATIC_HEAP_BYTES
#error "Must define number of heap bytes."
#endif

// Set a block size of 64 bytes. This means most allocations should be a single
// block.
#define SM_STATIC_HEAP_BLOCKSIZE 64
#define SM_STATIC_HEAP_BLOCKSIZE_LOG2 6
#define SM_STATIC_HEAP_BLOCKSIZE_MASK 0x3f
#define SM_STATIC_HEAP_NUM_BLOCKS                                              \
  (SM_STATIC_HEAP_BYTES / SM_STATIC_HEAP_BLOCKSIZE)

typedef struct {
  uint32_t alloc_num_blocks;
  void *ptr;
} block;

#define SM_STATIC_HEAP_BLOCK_STORAGE_SIZE                                      \
  (sizeof(block) * SM_STATIC_HEAP_NUM_BLOCKS)
#define SM_STATIC_HEAP_BITMAP_STORAGE_SIZE (SM_STATIC_HEAP_NUM_BLOCKS / 8)

// Static pointers/etc.
static uint8_t heap_[SM_STATIC_HEAP_BYTES];
// There are SM_STATIC_HEAP_BYTES / SM_STATIC_HEAP_BLOCKSIZE blocks.
static block *blocks = (block *)heap_;
// Tried a 2-level bitmap, and that actually slowed it down (I guess a cache
// locality issue, maybe?). Stick with single-level bitmap for now.
static uint64_t *bitmap = heap_ + SM_STATIC_HEAP_BLOCK_STORAGE_SIZE;
// heap_start begins after the block storage and after the bitmap.
const uint8_t *heap_start = heap_ + SM_STATIC_HEAP_BLOCK_STORAGE_SIZE +
                            SM_STATIC_HEAP_BITMAP_STORAGE_SIZE;
// heap_end is one past the end.
const uint8_t *heap_end = heap_ + SM_STATIC_HEAP_BYTES;

bool blocks_initialized(void) { return blocks[0].ptr != NULL; }

/// Initialize the block list pointers.
static void init_blocks(void) {
  uint8_t *iter = heap_start;
  for (size_t i = 0; i < SM_STATIC_HEAP_NUM_BLOCKS && iter < heap_end; ++i) {
    blocks[i].ptr = iter;
    iter += SM_STATIC_HEAP_BLOCKSIZE;
  }
}

/// Bitmap test/set/clear.
#define TEST_BLOCK(idx)                                                        \
  ((bitmap[(idx) >> SM_STATIC_HEAP_BLOCKSIZE_LOG2] >>                          \
    ((idx)&SM_STATIC_HEAP_BLOCKSIZE_MASK)) &                                   \
   1)

/// Takes n bits and allocates/frees them all in one bitwise operation.
#define ALLOC_BLOCKS(idx, n)                                                   \
  (bitmap[(idx) >> SM_STATIC_HEAP_BLOCKSIZE_LOG2] |=                           \
   ((1ull << (uint64_t)(n)) - 1) << ((idx)&SM_STATIC_HEAP_BLOCKSIZE_MASK))
#define FREE_BLOCKS(idx, n)                                                    \
  (bitmap[(idx) >> SM_STATIC_HEAP_BLOCKSIZE_LOG2] &=                           \
   ~(((1ull << (uint64_t)(n)) - 1) << ((idx)&SM_STATIC_HEAP_BLOCKSIZE_MASK)))

/// Find the first run of N blocks, and return the index of the first one. This
/// function is essentially a linear scan over the block list to find a free
/// run, but it has some tricks to skip groups of blocks when it's going to be
/// impossible to find enough blocks in this part of the bitmap.
static size_t find_first_block_run(int64_t num_blocks) {
  int64_t blocks_needed = num_blocks;
  size_t idx = SIZE_MAX;
  for (size_t i = 0, e = SM_STATIC_HEAP_NUM_BLOCKS; i < e;) {
    // If this bitmap instance cannot have enough blocks, skip these 64 blocks
    // entirely.
    if (__builtin_popcountll(~bitmap[i >> SM_STATIC_HEAP_BLOCKSIZE_LOG2]) <
        blocks_needed)
      i += 64;
    else
      ++i;

    if (TEST_BLOCK(i) == 0) {
      // If the index is unset, set it.
      if (idx == SIZE_MAX)
        idx = i;

      // If we have as many blocks as we need, we're done.
      if (--blocks_needed <= 0)
        break;

      // Continue - don't reset idx and blocks_needed.
      continue;
    }

    idx = SIZE_MAX;
    blocks_needed = num_blocks;
  }
  return idx;
}

/// Find a run of free blocks that will admit a slot of size `size`. This
/// essentially just forwards to find_first_block_run, but returns a pointer.
static uint8_t *find_alloc_slot(size_t size) {
  SM_ASSERT(size <= INT64_MAX);
  // Find the number of blocks, find the first run, and allocate them.
  int64_t num_blocks =
      ((int64_t)size + SM_STATIC_HEAP_BLOCKSIZE - 1) / SM_STATIC_HEAP_BLOCKSIZE;
  size_t block_idx_start = find_first_block_run(num_blocks);
  ALLOC_BLOCKS(block_idx_start, num_blocks);
  blocks[block_idx_start].alloc_num_blocks = num_blocks;
  return blocks[block_idx_start].ptr;
}

void *sm_malloc(size_t size) {
  if (!blocks_initialized())
    init_blocks();

  return find_alloc_slot(size);
}

void *sm_calloc(size_t count, size_t size) {
  void *ptr = sm_malloc(count * size);
  if (!ptr)
    return NULL;
  sm_memset(ptr, 0, count * size);
  return ptr;
}

/// Compute the block index of a given pointer. This can be done by comparing
/// the addresses and dividing by the block size.
#define LOOKUP_BLOCK(p)                                                        \
  (((uintptr_t)(p) - (uintptr_t)blocks[0].ptr) >> SM_STATIC_HEAP_BLOCKSIZE_LOG2)

void *sm_realloc(void *p, size_t newsz) {
  void *ptr = sm_malloc(newsz);
  if (!ptr)
    return NULL;

  // If we don't have an input pointer, behave like malloc.
  if (!p)
    return ptr;

  // Otherwise, find the block.
  size_t block_idx = LOOKUP_BLOCK(p);

  // Copy the memory over from one allocation to the new one.
  sm_memcpy(ptr, p,
            blocks[block_idx].alloc_num_blocks * SM_STATIC_HEAP_BLOCKSIZE);

  // Free the original pointer.
  sm_free(p);
  return ptr;
}

void *sm_safe_realloc(void *p, size_t newsz) {
  void *tmp = sm_realloc(p, newsz);
  SM_ASSERT(tmp != NULL);
  return tmp;
}

void sm_free(void *p) {
  if (!p)
    return;

  // Find the block whose pointer is `p`.
  size_t start_block = LOOKUP_BLOCK(p);
  // Now free all the blocks in the run.
  FREE_BLOCKS(start_block, blocks[start_block].alloc_num_blocks);
  // Memset to 0.
  sm_memset(p, 0,
            SM_STATIC_HEAP_BLOCKSIZE * blocks[start_block].alloc_num_blocks);
}

/// Basic strlen for use in strdup below.
static size_t strlen(const char *s) {
  size_t len = 0;
  while (*s++)
    ++len;

  return len;
}

char *sm_strdup(const char *s) {
  if (s == NULL)
    return NULL;

  size_t slen = strlen(s);
  // Malloc the new thing
  char *out = sm_malloc(slen + 1);
  if (!out)
    return NULL;

  // Copy the contents.
  sm_memcpy(out, s, slen);
  // Null-terminate the output.
  out[slen] = 0;
  return out;
}
