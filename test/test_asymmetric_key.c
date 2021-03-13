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

#include <bearssl.h>
#include <printf.h>

#include "smithy/crypto/asymmetric_key.h"
#include "smithy/stdlib/b64.h"

void ec() {
  SM_AUTO(br_ec_private_key) priv;
  SM_AUTO(br_ec_public_key) pub;

  sm_create_ec_keypair(SM_P256, &priv, &pub);

  // These are here so the resources get freed up
  sm_buffer priv_alias = sm_buffer_alias(priv.x, priv.xlen);
  sm_buffer pub_alias = sm_buffer_alias(pub.q, pub.qlen);
  (void)pub_alias;

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_serialize_ec_privkey(&priv, &der);

  br_skey_decoder_context ctx;
  br_skey_decoder_init(&ctx);
  br_skey_decoder_push(&ctx, sm_buffer_begin(der), der.length);
  int err = br_skey_decoder_last_error(&ctx);
  if (err != 0) {
    printf("decoder error: %d\n", err);
  }

  const br_ec_private_key *replicated = br_skey_decoder_get_ec(&ctx);
  SM_ASSERT(replicated->curve == priv.curve);
  sm_buffer repl_x = sm_buffer_alias(replicated->x, replicated->xlen);
  SM_ASSERT(sm_buffer_equal(priv_alias, repl_x));
}

void rsa() {
  SM_AUTO(br_rsa_private_key) priv;
  SM_AUTO(br_rsa_public_key) pub;

  sm_create_rsa_keypair(2048, &priv, &pub);
  sm_buffer p = sm_buffer_alias(priv.p, priv.plen);
  sm_buffer q = sm_buffer_alias(priv.q, priv.qlen);
  sm_buffer dp = sm_buffer_alias(priv.dp, priv.dplen);
  sm_buffer dq = sm_buffer_alias(priv.dq, priv.dqlen);
  sm_buffer iq = sm_buffer_alias(priv.iq, priv.iqlen);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_serialize_rsa_privkey(&priv, &der);

  br_skey_decoder_context ctx;
  br_skey_decoder_init(&ctx);
  br_skey_decoder_push(&ctx, sm_buffer_begin(der), der.length);
  int err = br_skey_decoder_last_error(&ctx);
  if (err != 0) {
    printf("decoder error: %d\n", err);
  }

  const br_rsa_private_key *replicated = br_skey_decoder_get_rsa(&ctx);
  sm_buffer r_p = sm_buffer_alias(replicated->p, replicated->plen);
  SM_ASSERT(sm_buffer_equal(p, r_p));
  sm_buffer r_q = sm_buffer_alias(replicated->q, replicated->qlen);
  SM_ASSERT(sm_buffer_equal(q, r_q));
  sm_buffer r_dp = sm_buffer_alias(replicated->dp, replicated->dplen);
  SM_ASSERT(sm_buffer_equal(dp, r_dp));
  sm_buffer r_dq = sm_buffer_alias(replicated->dq, replicated->dqlen);
  SM_ASSERT(sm_buffer_equal(dq, r_dq));
  sm_buffer r_iq = sm_buffer_alias(replicated->iq, replicated->iqlen);
  SM_ASSERT(sm_buffer_equal(iq, r_iq));
}

void ec_cert() {
  SM_AUTO(br_ec_private_key) priv;
  SM_AUTO(br_ec_public_key) pub;

  sm_create_ec_keypair(SM_P256, &priv, &pub);
  sm_buffer pub_alias = sm_buffer_alias(pub.q, pub.qlen);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_ec_pubkey_to_cert(&priv, &pub, &der);

  br_x509_decoder_context ctx;
  br_x509_decoder_init(&ctx, NULL, NULL);
  br_x509_decoder_push(&ctx, sm_buffer_begin(der), sm_buffer_length(der));
  int err = br_x509_decoder_last_error(&ctx);
  if (err != 0) {
    SM_FATAL("x509 decoder error: %d\n", err);
  }

  br_x509_pkey *key = br_x509_decoder_get_pkey(&ctx);
  br_ec_public_key *replicated = &key->key.ec;
  SM_ASSERT(replicated->curve == pub.curve);
  sm_buffer repl_q = sm_buffer_alias(replicated->q, replicated->qlen);
  SM_ASSERT(sm_buffer_equal(pub_alias, repl_q));
}

void rsa_cert() {
  SM_AUTO(br_rsa_private_key) priv;
  SM_AUTO(br_rsa_public_key) pub;

  sm_create_rsa_keypair(2048, &priv, &pub);
  sm_buffer n_alias = sm_buffer_alias(pub.n, pub.nlen);
  sm_buffer e_alias = sm_buffer_alias(pub.e, pub.elen);

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_rsa_pubkey_to_cert(&priv, &pub, &der);

  br_x509_decoder_context ctx;
  br_x509_decoder_init(&ctx, NULL, NULL);
  br_x509_decoder_push(&ctx, sm_buffer_begin(der), sm_buffer_length(der));
  int err = br_x509_decoder_last_error(&ctx);
  if (err != 0) {
    SM_FATAL("x509 decoder error: %d\n", err);
  }

  br_x509_pkey *key = br_x509_decoder_get_pkey(&ctx);
  br_rsa_public_key *replicated = &key->key.rsa;
  sm_buffer repl_n = sm_buffer_alias(replicated->n, replicated->nlen);
  sm_buffer repl_e = sm_buffer_alias(replicated->e, replicated->elen);
  SM_ASSERT(sm_buffer_equal(n_alias, repl_n));
  SM_ASSERT(sm_buffer_equal(e_alias, repl_e));
}

// NOTE: these two functions aren't currently tested by unit tests, but you can
// verify by adding the desired function to main and running the test
// executable. The CSR printed can be piped to: openssl req -text -noout

void ec_csr() {
  SM_AUTO(br_ec_private_key) priv;
  SM_AUTO(br_ec_public_key) pub;

  sm_create_ec_keypair(SM_P256, &priv, &pub);

  sm_buffer org = sm_buffer_alias_str("AnOrg");
  sm_buffer cn = sm_buffer_alias_str("CommonName");

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_ec_get_csr(&priv, &pub, org, cn, &der);

  SM_AUTO(sm_buffer) pem = sm_empty_buffer;
  sm_b64_encode(SM_B64_STANDARD_ENCODING, der, &pem);

  printf("-----BEGIN CERTIFICATE REQUEST-----\n");
  for (size_t i = 0; i < sm_buffer_length(pem); ++i) {
    printf("%c", sm_buffer_begin(pem)[i]);
    if (i % 59 == 0 && i != 0) {
      printf("\n");
    }
  }
  printf("\n-----END CERTIFICATE REQUEST-----\n");
}

void rsa_csr() {
  SM_AUTO(br_rsa_private_key) priv;
  SM_AUTO(br_rsa_public_key) pub;

  sm_create_rsa_keypair(2048, &priv, &pub);

  sm_buffer org = sm_buffer_alias_str("AnOrg");
  sm_buffer cn = sm_buffer_alias_str("CommonName");

  SM_AUTO(sm_buffer) der = sm_empty_buffer;
  sm_rsa_get_csr(&priv, &pub, org, cn, &der);

  SM_AUTO(sm_buffer) pem = sm_empty_buffer;
  sm_b64_encode(SM_B64_STANDARD_ENCODING, der, &pem);

  printf("-----BEGIN CERTIFICATE REQUEST-----\n");
  for (size_t i = 0; i < sm_buffer_length(pem); ++i) {
    printf("%c", sm_buffer_begin(pem)[i]);
    if (i % 59 == 0 && i != 0) {
      printf("\n");
    }
  }
  printf("\n-----END CERTIFICATE REQUEST-----\n");
}

int main() {
  ec();
  rsa();

  ec_cert();
  rsa_cert();

  ec_csr();
  rsa_csr();
}
