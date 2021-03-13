
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
#include "smithy/stdlib/b64.h"
#include "smithy/stdlib/memory.h"

void test_integer() {
  SM_AUTO(sm_der_node) i;
  sm_der_begin(SM_DER_TYPE_INTEGER, &i);
  sm_der_encode_integer(123475639487, &i);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_der_serialize(&i, &der);

  uint8_t correct[] = {0x02, 0x05, 0x1c, 0xbf, 0xb8, 0xbc, 0xbf};
  sm_buffer correct_buf = sm_buffer_alias(correct, sizeof(correct));
  SM_ASSERT(sm_buffer_equal(der, correct_buf));

  // Assert we can deserialize correctly
  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(correct_buf, &deser);
  SM_ASSERT(sm_der_tree_equal(&i, &deser) && error == SM_DER_ERROR_NONE);
}

void test_sequence() {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);
  SM_AUTO(sm_der_node) zero;
  sm_der_add(SM_DER_SEQ_NUMBER(0), &zero, &root);
  SM_AUTO(sm_der_node) version;
  sm_der_add(SM_DER_TYPE_INTEGER, &version, &zero);
  sm_der_encode_integer(12, &version);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_der_serialize(&root, &der);

  uint8_t correct[] = {0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x0c};
  sm_buffer correct_buf = sm_buffer_alias(correct, sizeof(correct));
  SM_ASSERT(sm_buffer_equal(der, correct_buf));

  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(correct_buf, &deser);
  SM_ASSERT(sm_der_tree_equal(&root, &deser) && error == SM_DER_ERROR_NONE);
}

void test_null() {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);
  SM_AUTO(sm_der_node) zero;
  sm_der_add(SM_DER_SEQ_NUMBER(0), &zero, &root);
  SM_AUTO(sm_der_node) null;
  sm_der_add(SM_DER_TYPE_NULL, &null, &zero);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_der_serialize(&root, &der);

  uint8_t correct[] = {0x30, 0x04, 0xa0, 0x02, 0x05, 0x00};
  sm_buffer correct_buf = sm_buffer_alias(correct, sizeof(correct));
  SM_ASSERT(sm_buffer_equal(der, correct_buf));

  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(correct_buf, &deser);
  SM_ASSERT(sm_der_tree_equal(&root, &deser) && error == SM_DER_ERROR_NONE);
}

void test_long_integer() {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_TYPE_INTEGER, &root);
  SM_AUTO(sm_buffer) bigint = sm_empty_buffer;
  sm_buffer_resize(&bigint, 256);
  sm_buffer_set(&bigint, 0, 0x80);
  sm_der_encode_bigint(bigint, true, &root);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_der_serialize(&root, &der);

  uint8_t correct[] = {0x02, 0x82, 0x01, 0x01, 0x00, 0x80};
  sm_buffer correct_buf = sm_buffer_alias(correct, sizeof(correct));
  sm_buffer der_alias = sm_buffer_alias(sm_buffer_begin(der), sizeof(correct));
  SM_ASSERT(sm_buffer_equal(der_alias, correct_buf));

  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(der, &deser);
  SM_ASSERT(sm_der_tree_equal(&root, &deser) && error == SM_DER_ERROR_NONE);
}

void test_oid() {
  SM_AUTO(sm_der_node) oid;
  sm_der_begin(SM_DER_TYPE_OBJECT_IDENTIFIER, &oid);
  // Encode the prime256v1 curve OID
  sm_der_oid_begin(1, 2, &oid);
  sm_der_oid_push(840, &oid);
  sm_der_oid_push(10045, &oid);
  sm_der_oid_push(3, &oid);
  sm_der_oid_push(1, &oid);
  sm_der_oid_push(7, &oid);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_der_serialize(&oid, &der);

  uint8_t correct[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                       0xce, 0x3d, 0x03, 0x01, 0x07};
  sm_buffer correct_buf = sm_buffer_alias(correct, sizeof(correct));
  SM_ASSERT(sm_buffer_equal(der, correct_buf));

  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(correct_buf, &deser);
  SM_ASSERT(sm_der_tree_equal(&oid, &deser) && error == SM_DER_ERROR_NONE);
}

void test_ec_privkey() {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);

  SM_AUTO(sm_der_node) version;
  sm_der_add(SM_DER_TYPE_INTEGER, &version, &root);
  sm_der_encode_integer(1, &version);

  SM_AUTO(sm_der_node) privkey;
  sm_der_add(SM_DER_TYPE_OCTET_STRING, &privkey, &root);
  SM_AUTO(sm_buffer) privkey_buf = sm_empty_buffer;
  sm_buffer_resize(&privkey_buf, 32);
  sm_memset(sm_buffer_begin(privkey_buf), 0xab, sm_buffer_length(privkey_buf));
  sm_der_encode_buffer(privkey_buf, &privkey);

  SM_AUTO(sm_der_node) params_tag;
  sm_der_add(SM_DER_SEQ_NUMBER(0), &params_tag, &root);
  SM_AUTO(sm_der_node) params;
  sm_der_add(SM_DER_TYPE_OBJECT_IDENTIFIER, &params, &params_tag);
  sm_der_oid_begin(1, 2, &params);
  sm_der_oid_push(840, &params);
  sm_der_oid_push(10045, &params);
  sm_der_oid_push(3, &params);
  sm_der_oid_push(1, &params);
  sm_der_oid_push(7, &params);

  SM_AUTO(sm_der_node) pubkey_tag;
  sm_der_add(SM_DER_SEQ_NUMBER(1), &pubkey_tag, &root);
  SM_AUTO(sm_der_node) pubkey;
  sm_der_add(SM_DER_TYPE_OCTET_STRING, &pubkey, &pubkey_tag);
  SM_AUTO(sm_buffer) pubkey_buf = sm_empty_buffer;
  sm_buffer_resize(&pubkey_buf, 32);
  sm_memset(sm_buffer_begin(pubkey_buf), 0xcd, sm_buffer_length(pubkey_buf));
  sm_der_encode_buffer(pubkey_buf, &pubkey);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_der_serialize(&root, &der);

  uint8_t correct[] = {
      0x30, 0x55, 0x02, 0x01, 0x01, 0x04, 0x20, 0xab, 0xab, 0xab, 0xab,
      0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
      0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
      0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xa0, 0x0a, 0x06, 0x08, 0x2a,
      0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x22, 0x04, 0x20,
      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};
  sm_buffer correct_buf = sm_buffer_alias(correct, sizeof(correct));
  SM_ASSERT(sm_buffer_equal(der, correct_buf));

  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(correct_buf, &deser);
  SM_ASSERT(sm_der_tree_equal(&root, &deser) && error == SM_DER_ERROR_NONE);
}

void test_rsa_pubkey() {
  SM_AUTO(sm_der_node) root;

  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);

  sm_der_node algorithm_id;
  sm_der_add(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &algorithm_id, &root);
  sm_der_node algorithm;
  sm_der_add(SM_DER_TYPE_OBJECT_IDENTIFIER, &algorithm, &algorithm_id);

  sm_der_oid_begin(1, 2, &algorithm);
  sm_der_oid_push(840, &algorithm);
  sm_der_oid_push(113549, &algorithm);
  sm_der_oid_push(1, &algorithm);
  sm_der_oid_push(1, &algorithm);
  sm_der_oid_push(1, &algorithm);

  // Parameters MUST be NULL
  sm_der_node parameters;
  sm_der_add(SM_DER_TYPE_NULL, &parameters, &algorithm_id);

  // Now encode the bit string
  sm_der_node pub_key;
  sm_der_add(SM_DER_CONSTRUCTED(SM_DER_TYPE_BIT_STRING), &pub_key, &root);

  sm_der_node rsa_pubkey_seq;
  sm_der_add(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &rsa_pubkey_seq,
             &pub_key);

  sm_der_node n;
  sm_der_add(SM_DER_TYPE_INTEGER, &n, &rsa_pubkey_seq);
  SM_AUTO(sm_buffer) n_buf = sm_empty_buffer;
  sm_buffer_resize(&n_buf, 32);
  sm_memset(sm_buffer_begin(n_buf), 0xab, sm_buffer_length(n_buf));
  sm_der_encode_bigint(n_buf, true, &n);

  sm_der_node e;
  sm_der_add(SM_DER_TYPE_INTEGER, &e, &rsa_pubkey_seq);
  uint8_t e_data[] = {0x01, 0x00, 0x01};
  sm_buffer e_alias = sm_buffer_alias(e_data, sizeof(e_data));
  SM_AUTO(sm_buffer) e_buf = sm_empty_buffer;
  sm_buffer_insert(&e_buf, sm_buffer_end(e_buf), sm_buffer_begin(e_alias),
                   sm_buffer_end(e_alias));
  sm_der_encode_buffer(e_alias, &e);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_der_serialize(&root, &der);

  uint8_t correct[] = {0x30, 0x3b, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
                       0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x23,
                       0x2a, 0x30, 0x28, 0x02, 0x21, 0x00, 0xab, 0xab, 0xab,
                       0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                       0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                       0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                       0xab, 0xab, 0x02, 0x03, 0x01, 0x00, 0x01};
  sm_buffer correct_buf = sm_buffer_alias(correct, sizeof(correct));
  SM_ASSERT(sm_buffer_equal(der, correct_buf));

  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(correct_buf, &deser);
  SM_ASSERT(sm_der_tree_equal(&root, &deser) && error == SM_DER_ERROR_NONE);
}

void test_get_child() {
  /*
   * The Public key structure looks like this
   * SubjectPublicKeyInfo  ::=  SEQUENCE  {
   *   algorithm         AlgorithmIdentifier,
   *   subjectPublicKey  BIT STRING
   * }
   *
   * AlgorithmIdentifier  ::=  SEQUENCE  {
   *    algorithm   OBJECT IDENTIFIER,
   *    parameters  ANY DEFINED BY algorithm OPTIONAL
   * }
   *
   * RSAPublicKey ::= SEQUENCE {
   *    modulus           INTEGER,  -- n
   *    publicExponent    INTEGER   -- e
   * }
   */
  uint8_t der[] = {0x30, 0x3b, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
                   0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x23,
                   0x2a, 0x30, 0x28, 0x02, 0x21, 0x00, 0xab, 0xab, 0xab,
                   0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                   0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                   0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                   0xab, 0xab, 0x02, 0x03, 0x01, 0x00, 0x01};
  sm_buffer der_buf = sm_buffer_alias(der, sizeof(der));
  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(der_buf, &deser);
  SM_ASSERT(error == SM_DER_ERROR_NONE);

  // So let's get the public key out of this DER.
  sm_der_node *bits = sm_der_get_child(&deser, 1);
  sm_der_node *seq = sm_der_get_child(bits, 0);
  sm_der_node *modulus = sm_der_get_child(seq, 0);
  uint64_t dummy;
  SM_ASSERT(SM_DER_ERROR_INVALID_OPERATION ==
            sm_der_decode_integer(modulus, &dummy));
  SM_AUTO(sm_buffer) intbuf = sm_empty_buffer;
  sm_der_decode_bigint(modulus, &intbuf);

  SM_AUTO(sm_buffer) n_buf = sm_empty_buffer;
  sm_buffer_resize(&n_buf, 32);
  sm_memset(sm_buffer_begin(n_buf), 0xab, sm_buffer_length(n_buf));

  SM_ASSERT(sm_buffer_equal(n_buf, intbuf));

  sm_der_node *pub_exp = sm_der_get_child(seq, 1);
  uint64_t pub;
  SM_ASSERT(sm_der_decode_integer(pub_exp, &pub) == SM_DER_ERROR_NONE);
  SM_ASSERT(pub == 0x010001);
}

// Testbed for debugging fuzzer failures.
void test_failure() {
  uint8_t der[] = {
      0x0,  0x0,  0x0,  0xa,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x8,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0xa,
  };
  sm_buffer der_buf = sm_buffer_alias(der, sizeof(der));
  SM_AUTO(sm_der_node) deser;
  sm_der_error error = sm_der_deserialize(der_buf, &deser);
  SM_ASSERT(error != SM_DER_ERROR_NONE);
}

int main() {
  // Basics
  test_integer();
  test_sequence();
  test_null();
  test_long_integer();
  test_oid();
  // More complex/nested structures
  test_ec_privkey();
  test_rsa_pubkey();

  test_get_child();
  test_failure();
}
