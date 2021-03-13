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

#include "smithy/crypto/der.h"

static size_t sm_der_length_num_octets(size_t length) {
  size_t msb_idx = ((sizeof(length) * 8) - __builtin_clzll(length | 1));
  // don't do ceiling division, for 7/8 we want it to return 0
  size_t num_octets = msb_idx / 8 + 1;
  return num_octets;
}

static size_t sm_der_vlq_num_octets(uint64_t val) {
  size_t msb_idx = ((sizeof(val) * 8) - __builtin_clzll(val | 1));
  size_t num_octets = (msb_idx + 7 - 1) / 7; // ceiling division
  return num_octets;
}

static void sm_der_encode_length(size_t length, sm_buffer *der) {
  if (length <= 0x7f) {
    // Definite short form, single length octet
    sm_buffer_push(der, (uint8_t)length);
  } else {
    // Definite long form is (num octets) | (length)
    size_t num_octets = sm_der_length_num_octets(length);
    uint8_t length_preamble = 0x80 | num_octets;
    sm_buffer_push(der, length_preamble);
    size_t mask = 0xffull << ((num_octets - 1) * 8);
    do {
      uint8_t value = (length & mask) >> ((num_octets - 1) * 8);
      sm_buffer_push(der, value);
      mask >>= 8;
      --num_octets;
    } while (mask != 0);
  }
}

static size_t sm_der_decode_length(const uint8_t *der, size_t max_octets,
                                   size_t *num_length_octets) {
  if (*der <= 0x7f) {
    *num_length_octets = 1;
    return *der;
  }

  uint8_t num_octets = *der & (~0x80);
  if (num_octets >= max_octets) {
    //    SM_DEBUG("DER decoding encountered a length that was too large\n");
    return SIZE_MAX;
  }
  size_t out = 0;
  for (uint8_t i = 0; i < num_octets; ++i) {
    out <<= 8;
    out |= der[i + 1];
  }

  // length octets plus one for length of length
  *num_length_octets = num_octets + 1;

  return out;
}

static void sm_der_encode_vlq_long_form(uint64_t value, sm_der_node *node) {
  size_t num_octets = sm_der_vlq_num_octets(value);
  node->len += num_octets;
  size_t mask = 0x7full << ((num_octets - 1) * 7);
  do {
    uint8_t val = (value & mask) >> ((num_octets - 1) * 7);
    sm_buffer_push(
        &node->data,
        val | 0x80); // high bit is set for octets that are not the first
    mask >>= 7;
    --num_octets;
  } while (mask != 0x7full);
  // Last octet
  uint8_t val = value & mask;
  sm_buffer_push(&node->data, val);
}

void sm_der_begin(uint8_t ty, sm_der_node *root) {
  root->type = ty;
  root->len = 0;
  root->data = sm_empty_buffer;
  root->n_children = 0;
  root->children = NULL;
}

void sm_der_cleanup(sm_der_node *root) {
  for (size_t i = 0; i < root->n_children; ++i) {
    sm_der_node *child = sm_ptr_u1_pair_get_ptr(root->children[i]);
    sm_der_cleanup(child);
    // Might have to free it
    if (sm_ptr_u1_pair_get_int(root->children[i]) == true) {
      sm_free(child);
    }
  }
  // Clean out the data
  root->type = 0;
  root->len = 0;
  sm_buffer_cleanup(root->data);
  root->data = sm_empty_buffer;
  root->n_children = 0;
  sm_free(root->children);
  root->children = NULL;
}

void sm_der_add(uint8_t ty, sm_der_node *child, sm_der_node *parent) {
  // List of pointers, expand it by 1
  void *tmp = sm_realloc(parent->children,
                         (parent->n_children + 1) * sizeof(sm_ptr_u1_pair));
  if (tmp == NULL) {
    SM_FATAL("realloc failed");
  }

  parent->children = tmp;
  parent->children[parent->n_children] = sm_ptr_u1_pair_false(child);
  ++parent->n_children;
  child->type = ty;
  child->len = 0;
  child->data = sm_empty_buffer;
  child->n_children = 0;
  child->children = NULL;
}

void sm_der_alloc(uint8_t ty, sm_der_node **child, sm_der_node *parent) {
  // List of pointers, expand it by 1
  void *tmp = sm_realloc(parent->children,
                         (parent->n_children + 1) * sizeof(sm_ptr_u1_pair));
  if (tmp == NULL) {
    SM_FATAL("realloc failed");
  }
  // Set up the child in the parent's array
  parent->children = tmp;
  // Alloc the child and set it in the parent's array
  sm_der_node *c = sm_calloc(1, sizeof(sm_der_node));
  parent->children[parent->n_children] = sm_ptr_u1_pair_true(c);

  // And the rest of the setup
  ++parent->n_children;
  c->type = ty;
  c->len = 0;
  c->data = sm_empty_buffer;
  c->n_children = 0;
  c->children = NULL;

  // Only set the child if it's not NULL
  if (child) {
    *child = c;
  }
}

void sm_der_encode_buffer(const sm_buffer buf, sm_der_node *node) {
  // Get the length
  node->len = sm_buffer_length(buf);
  // Handle BIT STRING types - for DER encoding it's always padded to 8 bits
  if (node->type == SM_DER_TYPE_BIT_STRING) {
    // Zero unused bits
    sm_buffer_push(&node->data, 0);
    ++node->len;
  }
  // And put the data into the buffer
  sm_buffer_insert(&node->data, sm_buffer_end(node->data), sm_buffer_begin(buf),
                   sm_buffer_end(buf));
}

void sm_der_encode_integer(uint64_t integer, sm_der_node *node) {
  // Get the length in number of octets
  size_t i_msb_idx = (64 - __builtin_clzll(integer | 1));
  size_t len = (i_msb_idx + 8 - 1) / 8; // ceiling division
  node->len = len; // store the number of octets in the integer
  uint64_t mask = 0xffull << ((len - 1) * 8);
  do {
    uint8_t val = (integer & mask) >> ((len - 1) * 8);
    sm_buffer_push(&node->data, val);
    mask >>= 8;
    --len;
  } while (mask != 0);
}

void sm_der_encode_bigint(const sm_buffer buf, bool pos, sm_der_node *node) {
  bool needs_leading_zero = pos && (sm_buffer_at(buf, 0) & 0x80) != 0;
  if (needs_leading_zero) {
    // This is only needed if the high bit is set - it's a positive number.
    // sm_der_encode_buffer places all the data at the end of the buffer, so
    // this is safe.
    sm_buffer_push(&node->data, 0);
  }

  sm_der_encode_buffer(buf, node);
  node->len += needs_leading_zero;
}

void sm_der_oid_begin(uint8_t first, uint8_t second, sm_der_node *node) {
  uint8_t first_octet = 40 * first + second;
  node->len = 1;
  sm_buffer_push(&node->data, first_octet);
}

void sm_der_oid_push(uint64_t val, sm_der_node *node) {
  if (val <= 0x7f) {
    // Short form, single octet
    sm_buffer_push(&node->data, (uint8_t)val);
    ++node->len;
  } else {
    sm_der_encode_vlq_long_form(val, node);
  }
}

sm_der_node *sm_der_get_child(sm_der_node *root, size_t which) {
  if (root->n_children <= which) {
    SM_ERROR("Root had %zu children, child %zu requested was invalid\n",
             root->n_children, which);
    return NULL;
  }

  return (sm_der_node *)sm_ptr_u1_pair_get_ptr(root->children[which]);
}

sm_der_error sm_der_decode_integer(sm_der_node *node, uint64_t *i) {
  if ((node->type & SM_DER_TYPE_MASK) != SM_DER_TYPE_INTEGER) {
    SM_DEBUG("Node was not an integer type, type: %x\n", node->type);
    return SM_DER_ERROR_INVALID_OPERATION;
  }

  if (node->len >= sizeof(uint64_t)) {
    SM_DEBUG(
        "Node bit length was too large for a single uint64_t, length: %zu\n",
        node->len);
    return SM_DER_ERROR_INVALID_OPERATION;
  }

  *i = *(uint64_t *)sm_buffer_begin(node->data);

  return SM_DER_ERROR_NONE;
}

sm_der_error sm_der_decode_bigint(sm_der_node *node, sm_buffer *buf) {
  if (node->len == 0) {
    SM_DEBUG("Node contained no data\n");
    return SM_DER_ERROR_NODE_EMPTY;
  }

  uint8_t *iter = sm_buffer_begin(node->data);
  if (*iter == 0) {
    ++iter;
  }

  sm_buffer_insert(buf, sm_buffer_end(*buf), iter, sm_buffer_end(node->data));
  return SM_DER_ERROR_NONE;
}

sm_der_error sm_der_decode_buffer(sm_der_node *node, sm_buffer *buf) {
  if (node->len == 0) {
    SM_DEBUG("Node contained no data\n");
    return SM_DER_ERROR_NODE_EMPTY;
  }
  sm_buffer_insert(buf, sm_buffer_end(*buf), sm_buffer_begin(node->data),
                   sm_buffer_end(node->data));
  return SM_DER_ERROR_NONE;
}

static void sm_der_update_subtree_len(sm_der_node *root, size_t *total) {
  // Use my length as the total for my children
  size_t subtotal = 0;
  for (size_t i = 0; i < root->n_children; ++i) {
    sm_der_update_subtree_len(sm_ptr_u1_pair_get_ptr(root->children[i]),
                              &subtotal);
  }

  if (root->len == 0) {
    root->len = subtotal;
  }

  size_t num_len_octets = sm_der_length_num_octets(root->len);
  if (num_len_octets > 1) {
    // Have to increment the number of length octets for the length of length
    // octets
    ++num_len_octets;
  }

  // Add my length, len(my length) onto the total, +1 for the type tag
  *total += root->len + num_len_octets + 1;
}

static void sm_der_clear_subtree_len(sm_der_node *root) {
  if (root->n_children == 0) {
    return;
  }

  // Clear out my children
  for (size_t i = 0; i < root->n_children; ++i) {
    sm_der_clear_subtree_len(sm_ptr_u1_pair_get_ptr(root->children[i]));
  }

  // Otherwise clear out the length
  root->len = 0;
}

static void sm_der_update_tree_len(sm_der_node *root) {
  // Special handling for the root
  size_t total = 0;
  // Length of my children == my length
  for (size_t i = 0; i < root->n_children; ++i) {
    sm_der_update_subtree_len(sm_ptr_u1_pair_get_ptr(root->children[i]),
                              &total);
  }

  if (root->len == 0) {
    root->len = total;
  }
}

void sm_der_serialize(sm_der_node *root, sm_buffer *der) {
  SM_ASSERT(root != NULL);

  // Update all the lengths in the subtree
  sm_der_update_tree_len(root);

  // Insert the type tag
  sm_buffer_push(der, root->type);
  // Get and encode the length if this node has no data
  if (sm_buffer_empty(root->data)) {
    size_t len = root->len;
    sm_buffer_reserve(der, len);
    sm_der_encode_length(len, der);
  } else {
    sm_der_encode_length(root->len, der);
    // Insert the root data first
    sm_buffer_insert(der, sm_buffer_end(*der), sm_buffer_begin(root->data),
                     sm_buffer_end(root->data));
  }
  // Then serialize the children
  for (size_t i = 0; i < root->n_children; ++i) {
    sm_der_serialize(sm_ptr_u1_pair_get_ptr(root->children[i]), der);
  }

  // Clear out lengths again so this can be applied again
  sm_der_clear_subtree_len(root);
}

static void sm_der_deser_helper(const sm_buffer der, sm_der_node *parent,
                                size_t *i, sm_der_error *error) {
#define CHECKED_INCREMENT(n)                                                   \
  do {                                                                         \
    if (*i >= der.length || *i + (n) > der.length) {                           \
      *error = SM_DER_ERROR_INVALID_INPUT;                                     \
      return;                                                                  \
    }                                                                          \
    *i += (n);                                                                 \
  } while (0)

  // If the error is already set, short-circuit.
  if (*error != SM_DER_ERROR_NONE) {
    return;
  }

  sm_der_node *work = NULL;
  size_t my_increment = 0;
  for (; *i < sm_buffer_length(der);) {
    // If I've incremented more than my parent's length then I should return.
    // This is to ensure that we exit a container at the right time
    if (my_increment >= parent->len && parent->type != 0) {
      return;
    }

    // Type tag is up first, if the parent is empty then use the parent as the
    // current work item.
    if (parent->type == 0 && work == NULL) {
      work = parent;
      sm_der_begin(der.data[*i], work);
    } else {
      sm_der_alloc(der.data[*i], &work, parent);
    }

    CHECKED_INCREMENT(1);
    size_t length_octets = 0;
    size_t len =
        sm_der_decode_length(der.data + *i, der.length - *i, &length_octets);
    if (len == SIZE_MAX) {
      *error = SM_DER_ERROR_INVALID_INPUT;
      return;
    }
    if (len >= der.length) {
      *error = SM_DER_ERROR_INVALID_INPUT;
      return;
    }
    work->len = len;
    CHECKED_INCREMENT(length_octets);

    // type + number of length octets
    my_increment += 1 + length_octets;

    if (work->type & SM_DER_CONSTRUCTED_MASK) {
      // If it's a constructed type then we have to add branches to the tree
      // Don't increment i here, it's going to be passed on to the deserialize
      // function
      sm_der_deser_helper(der, work, i, error);
    } else if (work->len == 0) {
      // Do nothing, nothing to copy.
    } else {
      // This is a leaf node, so grab the data and keep going. Do the increment
      // first and check it, that way we don't accidentally corrupt something.
      CHECKED_INCREMENT(work->len);
      work->data = sm_empty_buffer;
      sm_buffer_insert(&work->data, sm_buffer_end(work->data),
                       der.data + *i - work->len, der.data + *i);
      my_increment += work->len;
    }
  }
}

// Recursively serialize the children
sm_der_error sm_der_deserialize(const sm_buffer der, sm_der_node *root) {
  size_t top_level_idx = 0;
  sm_der_begin(0, root);
  sm_der_error error = SM_DER_ERROR_NONE;
  sm_der_deser_helper(der, root, &top_level_idx, &error);
  // If there was an error, clean up all the children.
  if (error != SM_DER_ERROR_NONE) {
    sm_der_cleanup(root);
  }

  return error;
}

char *der_type_strings[] = {"END",
                            "BOOLEAN",
                            "INTEGER",
                            "BIT_STRING",
                            "OCTET_STRING",
                            "NULL",
                            "OBJECT_IDENTIFIER",
                            "OBJECT_DESCRIPTOR",
                            "EXTERNAL",
                            "REAL",
                            "ENUMERATED",
                            "EMBEDDED_PDV",
                            "UTF8_STRING",
                            "RELATIVE_OID",
                            "TIME",
                            "RESERVED",
                            "SEQUENCE",
                            "SET",
                            "NUMERIC_STRING",
                            "PRINTABLE_STRING",
                            "T61_STRING",
                            "VIDEOTEX_STRING",
                            "IA5_STRING",
                            "UTC_TIME",
                            "GENERALIZED_TIME",
                            "GRAPHIC_STRING",
                            "VISIBLE_STRING",
                            "GENERAL_STRING",
                            "UNIVERSAL_STRING",
                            "CHARACTER_STRING",
                            "BMP_STRING",
                            "DATE",
                            "TIME_OF_DAY",
                            "DATE_TIME",
                            "DURATION",
                            "OID_IRI",
                            "RELATIVE_OID_IRI"};

static char *der_type_str(uint8_t ty) {
  return der_type_strings[ty & SM_DER_TYPE_MASK];
}

static void sm_der_dump_helper(sm_buffer *buf, sm_der_node *root, int indent) {
  for (int i = 0; i < indent; ++i) {
    sm_buffer_push(buf, '\t');
  }

  // If it has a sequence number, print it
  if (root->type & 0x80) {
    sm_buffer_print(buf, "[%d] (len:0x%zx) ", root->type & SM_DER_TYPE_MASK,
                    root->len);
  } else {
    sm_buffer_print(buf, "%s:0x%x len:0x%zx ", der_type_str(root->type),
                    root->type, root->len);
  }

  if (root->n_children != 0) {
    sm_buffer_print(buf, "{\n");
  } else if (!sm_buffer_empty(root->data)) {
    sm_buffer_print(buf, "data: ");
  }
  for (size_t i = 0, e = sm_buffer_length(root->data); i < e; ++i) {
    sm_buffer_print(buf, "%.2x", sm_buffer_begin(root->data)[i]);
  }
  for (size_t i = 0; i < root->n_children; ++i) {
    sm_der_dump_helper(buf, sm_ptr_u1_pair_get_ptr(root->children[i]),
                       indent + 1);
  }
  if (root->n_children != 0) {
    for (int i = 0; i < indent; ++i) {
      sm_buffer_push(buf, '\t');
    }

    sm_buffer_push(buf, '}');
  }
  sm_buffer_push(buf, '\n');
}

void sm_der_dump(sm_der_node *root) {
  sm_der_update_tree_len(root);
  SM_AUTO(sm_buffer) out = sm_empty_buffer;
  sm_der_dump_helper(&out, root, 0);

  SM_DEBUG("DER dump:\n%.*s", out.length, sm_buffer_begin(out));
  sm_der_clear_subtree_len(root);
}

bool sm_der_tree_equal(const sm_der_node *lhs, const sm_der_node *rhs) {
  // DFS, compare parent then children
  if (lhs->type != rhs->type) {
    return false;
  }

  if (lhs->n_children != rhs->n_children) {
    return false;
  }

  if (!sm_buffer_equal(lhs->data, rhs->data)) {
    return false;
  }

  for (size_t i = 0; i < lhs->n_children; ++i) {
    sm_der_node *lhs_child = sm_ptr_u1_pair_get_ptr(lhs->children[i]);
    sm_der_node *rhs_child = sm_ptr_u1_pair_get_ptr(rhs->children[i]);

    // Break early if any of the children don't match
    if (!sm_der_tree_equal(lhs_child, rhs_child)) {
      return false;
    }
  }

  return true;
}
