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

#include <stdint.h>
#include <stdlib.h>

#include "smithy/stdlib/buffer.h"
#include "smithy/stdlib/ptr_int_pair.h"

/// All DER node types.
typedef enum {
  SM_DER_TYPE_END = 0x0,
  SM_DER_TYPE_BOOLEAN = 0x1,
  SM_DER_TYPE_INTEGER = 0x2,
  SM_DER_TYPE_BIT_STRING = 0x3,
  SM_DER_TYPE_OCTET_STRING = 0x4,
  SM_DER_TYPE_NULL = 0x5,
  SM_DER_TYPE_OBJECT_IDENTIFIER = 0x6,
  SM_DER_TYPE_OBJECT_DESCRIPTOR = 0x7,
  SM_DER_TYPE_EXTERNAL = 0x8,
  SM_DER_TYPE_REAL = 0x9,
  SM_DER_TYPE_ENUMERATED = 0xa,
  SM_DER_TYPE_EMBEDDED_PDV = 0xb,
  SM_DER_TYPE_UTF8_STRING = 0xc,
  SM_DER_TYPE_RELATIVE_OID = 0xd,
  SM_DER_TYPE_TIME = 0xe,
  SM_DER_TYPE_RESERVED = 0xf,
  SM_DER_TYPE_SEQUENCE = 0x10,
  SM_DER_TYPE_SET = 0x11,
  SM_DER_TYPE_NUMERIC_STRING = 0x12,
  SM_DER_TYPE_PRINTABLE_STRING = 0x13,
  SM_DER_TYPE_T61_STRING = 0x14,
  SM_DER_TYPE_VIDEOTEX_STRING = 0x15,
  SM_DER_TYPE_IA5_STRING = 0x16,
  SM_DER_TYPE_UTC_TIME = 0x17,
  SM_DER_TYPE_GENERALIZED_TIME = 0x18,
  SM_DER_TYPE_GRAPHIC_STRING = 0x19,
  SM_DER_TYPE_VISIBLE_STRING = 0x1a,
  SM_DER_TYPE_GENERAL_STRING = 0x1b,
  SM_DER_TYPE_UNIVERSAL_STRING = 0x1c,
  SM_DER_TYPE_CHARACTER_STRING = 0x1d,
  SM_DER_TYPE_BMP_STRING = 0x1e,
  SM_DER_TYPE_DATE = 0x1f,
  SM_DER_TYPE_TIME_OF_DAY = 0x20,
  SM_DER_TYPE_DATE_TIME = 0x21,
  SM_DER_TYPE_DURATION = 0x22,
  SM_DER_TYPE_OID_IRI = 0x23,
  SM_DER_TYPE_RELATIVE_OID_IRI = 0x24,
} sm_der_asn1_type;

/// Helpful definitions for DER manipulation.
#define SM_DER_CONSTRUCTED_MASK 0x20
#define SM_DER_TYPE_MASK 0x1f
#define SM_DER_CONSTRUCTED(tag) ((tag) | SM_DER_CONSTRUCTED_MASK)
#define SM_DER_APPLICATION(tag) ((tag) | 0x40)
#define SM_DER_CONTEXT(tag) ((tag) | 0x80)
#define SM_DER_PRIVATE(tag) ((tag) | 0xc0)
#define SM_DER_SEQ_MASK SM_DER_CONTEXT(SM_DER_CONSTRUCTED_MASK)
#define SM_DER_SEQ_NUMBER(idx) SM_DER_CONTEXT(SM_DER_CONSTRUCTED((idx)))

/// DER is express-able as a tree of objects where the length of each node is
/// the sum of the lengths and tags of its children. Most of this structure
/// shall be considered opaque.
typedef struct sm_der_node_ {
  uint8_t type;
  size_t len;
  sm_buffer data;
  // Do not edit the following fields.
  size_t n_children;
  /// Array of pointers (the ptr_u1_pair has a pointer in it)
  sm_ptr_u1_pair *children;
} sm_der_node;

/// With an initial type and an sm_der_node root, begin a DER tree.
void sm_der_begin(uint8_t ty, sm_der_node *root);
/// Clean up the tree. This frees all owned memory nested under `root`.
void sm_der_cleanup(sm_der_node *root);

/// Needed for SM_AUTO macro
static inline void free_sm_der_node(sm_der_node *n) { sm_der_cleanup(n); }

/// Add a child node of type `ty` to `parent`. The lifetime of `child` must be
/// managed by the caller and must be alive until the tree is serialized.
void sm_der_add(uint8_t ty, sm_der_node *child, sm_der_node *parent);
/// Add a child node of type `ty` to `parent`. Allocate `child` and mark it as
/// owned in `parent` so that when `parent` is freed, `child` will be also. The
/// caller is not responsible for the memory of `child` and it should NOT free
/// the result pointer.
void sm_der_alloc(uint8_t ty, sm_der_node **child, sm_der_node *parent);
/// DER encode `buf` and place it into `node`.
void sm_der_encode_buffer(const sm_buffer buf, sm_der_node *node);
/// DER encode `integer` and place it into `node`.
void sm_der_encode_integer(uint64_t integer, sm_der_node *node);
/// DER encode a biginteger represented by `buf` (with a sign bit `pos`) and
/// place it into `node`.
void sm_der_encode_bigint(const sm_buffer buf, bool pos, sm_der_node *node);
/// Handle the DER OBJECT_IDENTIFIER node. OIDs must have the first 2 octets
/// specified. This simply begins an OID node, additional values may be added
/// with `sm_der_oid_push`.
void sm_der_oid_begin(uint8_t first, uint8_t second, sm_der_node *node);
/// Push OID values onto the given OID node. The node must have had
/// `sm_der_oid_begin` called.
void sm_der_oid_push(uint64_t val, sm_der_node *node);

/// Get a child node of the given node. Returns NULL if `which` is out of range.
/// It is inadvisable to add this back into the DER tree as the structure may be
/// owned by the root object.
sm_der_node *sm_der_get_child(sm_der_node *root, size_t which);

/// Get the type of the node.
static inline sm_der_asn1_type sm_der_get_type(sm_der_node *node) {
  return node->type & SM_DER_TYPE_MASK;
}

/// Check if the node is a DER_CONSTRUCTED type.
static inline bool sm_der_is_constructed(sm_der_node *node) {
  return (node->type & SM_DER_CONSTRUCTED_MASK) != 0;
}

typedef enum {
  SM_DER_ERROR_NONE, // Everything is OK
  SM_DER_ERROR_INVALID_OPERATION,
  SM_DER_ERROR_NODE_EMPTY,
  SM_DER_ERROR_INVALID_INPUT,
} sm_der_error;

/// Decode DER nodes.
sm_der_error sm_der_decode_integer(sm_der_node *node, uint64_t *i);
sm_der_error sm_der_decode_bigint(sm_der_node *node, sm_buffer *buf);
sm_der_error sm_der_decode_buffer(sm_der_node *node, sm_buffer *buf);

/// Serialize/Deserialize the whole tree anchored at root
void sm_der_serialize(sm_der_node *root, sm_buffer *der);
sm_der_error sm_der_deserialize(const sm_buffer der, sm_der_node *root);

/// Debug helpers - dump and check for equality.
void sm_der_dump(sm_der_node *root);
bool sm_der_tree_equal(const sm_der_node *lhs, const sm_der_node *rhs);
