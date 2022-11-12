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

#include "smithy/crypto/cert_chain.h"
#include "smithy/stdlib/b64.h"
#include "smithy/stdlib/logging.h"

#include <string.h>

void sm_certificate_chain_init(sm_certificate_chain *chain, sm_trust_store *t,
                               const char *server_name) {
  // Initialize the context
  br_x509_minimal_init(&chain->ctx, &br_sha256_vtable, t->anchors,
                       t->num_anchors);

  // Disable insecure hash functions
  br_x509_minimal_set_hash(&chain->ctx, br_md5_ID, NULL);
  br_x509_minimal_set_hash(&chain->ctx, br_sha1_ID, NULL);
  // Enable secure hash functions
  br_x509_minimal_set_hash(&chain->ctx, br_sha224_ID, &br_sha224_vtable);
  br_x509_minimal_set_hash(&chain->ctx, br_sha256_ID, &br_sha256_vtable);
  br_x509_minimal_set_hash(&chain->ctx, br_sha384_ID, &br_sha384_vtable);
  br_x509_minimal_set_hash(&chain->ctx, br_sha512_ID, &br_sha512_vtable);

  // Initialize the rsa verification vtable
  br_x509_minimal_set_rsa(&chain->ctx, br_rsa_pkcs1_vrfy_get_default());
  // Initialize the ecdsa verification vtable
  br_x509_minimal_set_ecdsa(&chain->ctx, br_ec_get_default(),
                            br_ecdsa_vrfy_asn1_get_default());

  // Start the chain
  const br_x509_class **x509 = (void *)&chain->ctx;
  (*x509)->start_chain(x509, server_name);
}

void sm_certificate_chain_cleanup(const sm_certificate_chain *chain) {
  (void)chain;
}

#define BEGIN "BEGIN"
#define END "END"
#define CERT "CERTIFICATE"

static bool is_line_cert_banner(char *line) {
  size_t len = strlen(line);

  // 5 dashes on each side, plus the word "END"
  if (len < 5 + 3 + 1 + strlen(CERT) + 5) {
    return false;
  }

  bool is_banner = true;

  // Check the first 5 characters of the line for the banner
  for (size_t i = 0; i < 5; ++i) {
    is_banner &= line[i] == '-';
  }
  // Bail early if it's not a banner
  if (!is_banner) {
    return false;
  }

  char *saveptr = NULL;

  // Now check for the "BEGIN" or "END"
  char *maybe = strtok_r(&line[5], " ", &saveptr);
  int is_begin = strncmp(maybe, BEGIN, strlen(BEGIN));
  int is_end = strncmp(maybe, END, strlen(END));
  // No BEGIN or END, not a banner
  if (is_begin != 0 && is_end != 0) {
    return false;
  }
  // Otherwise, found either BEGIN or END so it is a banner. Now check if it's a
  // certificate
  char *rest = strtok_r(NULL, " ", &saveptr);
  int is_cert = strncmp(rest, CERT, strlen(CERT));
  if (is_cert != 0) {
    // Not a certificate
    return false;
  }

  rest += strlen(CERT);
  for (size_t i = 0; i < 5; ++i) {
    is_banner &= *(rest++) == '-';
  }
  if (!is_banner) {
    return false;
  }

  // And the final newline on the banner
  return true;
}

bool sm_add_pem_certificate_to_chain(sm_certificate_chain *chain,
                                     const sm_buffer pem) {
  // Strip the pem header
  uint8_t *iter = sm_buffer_begin(pem);
  if (iter == NULL) {
    SM_ERROR("No data\n");
    return false;
  }

  char *saveptr = NULL;
  // Look for the first newline, that'll be the end of the banner
  char *str = strtok_r((char *)iter, "\n", &saveptr);
  if (!is_line_cert_banner(str)) {
    SM_ERROR("Malformed PEM\n");
    return false;
  }

  SM_AUTO(sm_buffer) data_buf = sm_empty_buffer;

  str = strtok_r(NULL, "\n", &saveptr);
  while (str) {
    if (is_line_cert_banner(str)) {
      break;
    }
    sm_buffer_insert(&data_buf, sm_buffer_end(data_buf), (uint8_t *)str,
                     (uint8_t *)str + strlen(str));
    str = strtok_r(NULL, "\n", &saveptr);
  }

  // This will place the raw DER encoded contents into der_buf
  SM_AUTO(sm_buffer) der_buf = sm_empty_buffer;
  if (!sm_b64_decode(SM_B64_STANDARD_ENCODING, data_buf, &der_buf)) {
    SM_ERROR("Unable to b64 decode the PEM contents\n");
    return false;
  }

  sm_add_der_certificate_to_chain(chain, der_buf);
  return true;
}

void sm_add_der_certificate_to_chain(sm_certificate_chain *chain,
                                     const sm_buffer der) {
  const br_x509_class **x509 = (void *)&chain->ctx;

  // Add the certificate to the x509 validator
  (*x509)->start_cert(x509, sm_buffer_length(der));
  (*x509)->append(x509, sm_buffer_begin(der), sm_buffer_length(der));
  (*x509)->end_cert(x509);
}

bool sm_finish_certificate_chain(sm_certificate_chain *chain) {
  const br_x509_class **x509 = (void *)&chain->ctx;
  unsigned success = (*x509)->end_chain(x509);
  if (success != 0) {
    SM_ERROR("Unable to validate the certificate chain: %u\n", success);
    return false;
  }
  return true;
}

const br_x509_pkey *sm_get_end_entity_key(const sm_certificate_chain *chain,
                                          unsigned *usage) {
  const br_x509_class **x509 = (void *)&chain->ctx;
  return (*x509)->get_pkey(x509, usage);
}
