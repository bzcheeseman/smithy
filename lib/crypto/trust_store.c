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

#include "smithy/crypto/trust_store.h"
#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/logging.h"

void sm_trust_store_init(sm_trust_store *t) {
  t->anchors = NULL;
  t->num_anchors = 0;
}

static void free_trust_anchor(br_x509_trust_anchor *anchor) {
  // Free the key
  if (anchor->pkey.key_type & BR_KEYTYPE_RSA) {
    sm_free(anchor->pkey.key.rsa.n);
    sm_free(anchor->pkey.key.rsa.e);
  }

  if (anchor->pkey.key_type & BR_KEYTYPE_EC) {
    sm_free(anchor->pkey.key.ec.q);
  }

  // Free the DN
  sm_free(anchor->dn.data);
}

void sm_trust_store_cleanup(sm_trust_store *t) {
  for (size_t i = 0; i < t->num_anchors; ++i) {
    free_trust_anchor(&t->anchors[i]);
  }
  sm_free(t->anchors);
  t->num_anchors = 0;
}

// Callbacks for decoding the trust anchors
static void read_dn(void *ctx, const void *buf, size_t len) {
  sm_buffer *dn_buf = ctx;
  sm_buffer_insert(dn_buf, sm_buffer_end(*dn_buf), (const uint8_t *)buf,
                   (const uint8_t *)buf + len);
}

static inline void pkey_decoder(void *ctx, const void *data, size_t data_len) {
  br_x509_decoder_push(ctx, data, data_len);
}

void sm_add_trust_anchor(sm_trust_store *t, const sm_buffer ta) {
  br_x509_decoder_context decoder_ctx;

  // Read the DN for the trust anchor. Don't use SM_AUTO because we
  // actually don't want to free the buffer yet.
  sm_buffer dn_buf = sm_empty_buffer;
  br_x509_decoder_init(&decoder_ctx, &read_dn, &dn_buf);

  br_pem_decoder_context ctx;
  br_pem_decoder_init(&ctx);

  // Copy the data into the signing key
  br_pem_decoder_setdest(&ctx, &pkey_decoder, &decoder_ctx);

  // Decode the pem object
  uint8_t *iter = sm_buffer_begin(ta);
  size_t decoded = br_pem_decoder_push(&ctx, iter, sm_buffer_length(ta));
  iter += decoded;
  size_t len = sm_buffer_length(ta) - decoded;
  while (decoded < sm_buffer_length(ta)) {
    int event = br_pem_decoder_event(&ctx);
    // If the event is the end of the object, then break the loop
    if (event == BR_PEM_END_OBJ) {
      break;
    } else if (event == BR_PEM_ERROR) {
      SM_FATAL("PEM decoding failed\n");
      break;
    }
    size_t d = br_pem_decoder_push(&ctx, iter, len);
    iter += d;
    len -= d;
    decoded += d;
  }

  int err = br_x509_decoder_last_error(&decoder_ctx);
  SM_ASSERT(err == 0 && "X509 decoding failed");

  void *tmp = sm_realloc(t->anchors,
                         sizeof(br_x509_trust_anchor) * (t->num_anchors + 1));
  SM_ASSERT(tmp && "Realloc failed");
  t->anchors = tmp;

  br_x509_trust_anchor *anchor = &t->anchors[t->num_anchors];
  ++(t->num_anchors);

  // The buffer data won't be freed here, it'll be freed at cleanup
  anchor->dn.data = sm_buffer_begin(dn_buf);
  anchor->dn.len = dn_buf.length;

  // The anchor is a CA
  anchor->flags = BR_X509_TA_CA;

  // Copy the key into the anchor
  br_x509_pkey *pkey = br_x509_decoder_get_pkey(&decoder_ctx);
  // Grab the key type
  anchor->pkey.key_type = pkey->key_type;
  // And copy the other traits
  if (pkey->key_type & BR_KEYTYPE_EC) {
    const br_ec_public_key key = pkey->key.ec;
    anchor->pkey.key.ec.curve = key.curve;
    anchor->pkey.key.ec.q = sm_calloc(key.qlen, 1);
    anchor->pkey.key.ec.qlen = key.qlen;
    memcpy(anchor->pkey.key.ec.q, key.q, key.qlen);
  } else if (pkey->key_type & BR_KEYTYPE_RSA) {
    const br_rsa_public_key key = pkey->key.rsa;
    anchor->pkey.key.rsa.n = sm_calloc(key.nlen, 1);
    anchor->pkey.key.rsa.nlen = key.nlen;
    memcpy(anchor->pkey.key.rsa.n, key.n, key.nlen);
    anchor->pkey.key.rsa.e = sm_calloc(key.elen, 1);
    anchor->pkey.key.rsa.elen = key.elen;
    memcpy(anchor->pkey.key.rsa.e, key.e, key.elen);
  }
}
