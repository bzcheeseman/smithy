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

void ec(void) {
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

void rsa(void) {
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

void ec_cert(void) {
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

void rsa_cert(void) {
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

void ec_csr(void) {
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

void rsa_csr(void) {
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

void rsa_crypt_nolabel(void) {
  SM_AUTO(br_rsa_private_key) priv;
  SM_AUTO(br_rsa_public_key) pub;

  sm_create_rsa_keypair(2048, &priv, &pub);

  SM_AUTO(sm_buffer) plaintext = sm_empty_buffer;
  SM_AUTO(sm_buffer) ciphertext = sm_empty_buffer;

  // This is too big, but use it to ensure we get the error we expect.
  sm_buffer_resize(&plaintext, 256);
  sm_buffer_fill_rand(plaintext, sm_buffer_begin(plaintext),
                      sm_buffer_end(plaintext));

  SM_INFO("Expected error: ");
  SM_ASSERT(!sm_rsa_encrypt(&pub, plaintext, sm_empty_buffer, &ciphertext));

  // Now resize it to the correct size.
  sm_buffer_resize(&plaintext, 32);
  SM_ASSERT(sm_rsa_encrypt(&pub, plaintext, sm_empty_buffer, &ciphertext));

  // Check that it wasn't a no-op.
  SM_ASSERT(!sm_buffer_equal(plaintext, ciphertext));

  // And ensure it decrypts properly.
  SM_ASSERT(sm_rsa_decrypt(&priv, &ciphertext, sm_empty_buffer));

  // Ensure they're exactly equal.
  SM_ASSERT(sm_buffer_equal(plaintext, ciphertext));
}

void rsa_crypt_withlabel(void) {
  SM_AUTO(br_rsa_private_key) priv;
  SM_AUTO(br_rsa_public_key) pub;

  sm_create_rsa_keypair(2048, &priv, &pub);

  SM_AUTO(sm_buffer) plaintext = sm_empty_buffer;
  SM_AUTO(sm_buffer) ciphertext = sm_empty_buffer;
  SM_AUTO(sm_buffer) label = sm_empty_buffer;

  // Use a large label here.
  sm_buffer_resize(&label, 1024);
  sm_buffer_fill_rand(label, sm_buffer_begin(label), sm_buffer_end(label));

  // This is too big, but use it to ensure we get the error we expect.
  sm_buffer_resize(&plaintext, 1234);
  sm_buffer_fill_rand(plaintext, sm_buffer_begin(plaintext),
                      sm_buffer_end(plaintext));

  SM_INFO("Expected error: ");
  SM_ASSERT(!sm_rsa_encrypt(&pub, plaintext, label, &ciphertext));

  // Now resize it to the correct size.
  sm_buffer_resize(&plaintext, 32);
  SM_ASSERT(sm_rsa_encrypt(&pub, plaintext, label, &ciphertext));

  // Check that it wasn't a no-op.
  SM_ASSERT(!sm_buffer_equal(plaintext, ciphertext));

  // And ensure it decrypts properly.
  SM_ASSERT(sm_rsa_decrypt(&priv, &ciphertext, label));

  // Ensure they're exactly equal.
  SM_ASSERT(sm_buffer_equal(plaintext, ciphertext));
}

void ec_keyx(void) {
  SM_AUTO(br_ec_private_key) priv_me;
  SM_AUTO(br_ec_public_key) pub_me;
  sm_create_ec_keypair(SM_P256, &priv_me, &pub_me);

  SM_AUTO(br_ec_private_key) priv_peer;
  SM_AUTO(br_ec_public_key) pub_peer;
  sm_create_ec_keypair(SM_P256, &priv_peer, &pub_peer);

  // Generate the shared secret using my private key and my peer's public key.
  SM_AUTO(sm_buffer) me_peer_secret = sm_empty_buffer;
  SM_ASSERT(sm_ec_keyx(&priv_me, &pub_peer, &me_peer_secret));

  // Generate the (hopefully) same shared secret using my peer's private key and
  // my public key.
  SM_AUTO(sm_buffer) peer_me_secret = sm_empty_buffer;
  SM_ASSERT(sm_ec_keyx(&priv_peer, &pub_me, &peer_me_secret));

  // Assert that the two secrets are the same.
  SM_ASSERT(sm_buffer_equal(me_peer_secret, peer_me_secret));
}

void asymmetric_ec(void) {
  SM_AUTO(sm_asymmetric_private_key) priv_me;
  SM_AUTO(sm_asymmetric_public_key) pub_me;
  sm_create_asymmetric_keypair(SM_P256, &priv_me, &pub_me);

  SM_AUTO(sm_asymmetric_private_key) priv_peer;
  SM_AUTO(sm_asymmetric_public_key) pub_peer;
  sm_create_asymmetric_keypair(SM_P256, &priv_peer, &pub_peer);

  SM_AUTO(sm_buffer) plaintext = sm_empty_buffer;
  SM_AUTO(sm_buffer) ciphertext = sm_empty_buffer;
  SM_AUTO(sm_buffer) aad = sm_empty_buffer;

  sm_buffer_resize(&plaintext, 2956);
  sm_buffer_fill_rand(plaintext, sm_buffer_begin(plaintext),
                      sm_buffer_end(plaintext));

  // Put some data into the AAD that we can check on decrypt.
  sm_buffer_resize(&aad, 1234);
  sm_buffer_fill_rand(aad, sm_buffer_begin(aad), sm_buffer_end(aad));
  SM_AUTO(sm_buffer) cloned_aad = sm_buffer_clone(aad);

  SM_ASSERT(
      sm_asymmetric_encrypt(&priv_me, &pub_peer, plaintext, &ciphertext, &aad));

  // Ensure it wasn't a no-op.
  SM_ASSERT(!sm_buffer_equal(plaintext, ciphertext));

  SM_AUTO(sm_buffer) decrypted = sm_empty_buffer;
  SM_ASSERT(
      sm_asymmetric_decrypt(&priv_peer, &pub_me, ciphertext, &aad, &decrypted));

  // Ensure the AAD is exactly what we put in.
  SM_ASSERT(sm_buffer_equal(cloned_aad, aad));
  // And ensure the data decrypted properly.
  SM_ASSERT(sm_buffer_equal(decrypted, plaintext));
}

void asymmetric_rsa(void) {
  SM_AUTO(sm_asymmetric_private_key) priv_me;
  SM_AUTO(sm_asymmetric_public_key) pub_me;
  sm_create_asymmetric_keypair(2048, &priv_me, &pub_me);

  SM_AUTO(sm_asymmetric_private_key) priv_peer;
  SM_AUTO(sm_asymmetric_public_key) pub_peer;
  sm_create_asymmetric_keypair(2048, &priv_peer, &pub_peer);

  SM_AUTO(sm_buffer) plaintext = sm_empty_buffer;
  SM_AUTO(sm_buffer) ciphertext = sm_empty_buffer;
  SM_AUTO(sm_buffer) aad = sm_empty_buffer;

  sm_buffer_resize(&plaintext, 2956);
  sm_buffer_fill_rand(plaintext, sm_buffer_begin(plaintext),
                      sm_buffer_end(plaintext));

  // Put some data into the AAD that we can check on decrypt.
  sm_buffer_resize(&aad, 1234);
  sm_buffer_fill_rand(aad, sm_buffer_begin(aad), sm_buffer_end(aad));
  SM_AUTO(sm_buffer) cloned_aad = sm_buffer_clone(aad);

  SM_ASSERT(
      sm_asymmetric_encrypt(&priv_me, &pub_peer, plaintext, &ciphertext, &aad));

  // Ensure it wasn't a no-op.
  SM_ASSERT(!sm_buffer_equal(plaintext, ciphertext));

  SM_AUTO(sm_buffer) decrypted = sm_empty_buffer;
  SM_ASSERT(
      sm_asymmetric_decrypt(&priv_peer, &pub_me, ciphertext, &aad, &decrypted));

  // Ensure the AAD is exactly what we put in.
  SM_ASSERT(sm_buffer_equal(cloned_aad, aad));
  // And ensure the data decrypted properly.
  SM_ASSERT(sm_buffer_equal(decrypted, plaintext));
}

int main(void) {
  ec();
  rsa();

  ec_cert();
  rsa_cert();

  ec_csr();
  rsa_csr();

  rsa_crypt_nolabel();
  rsa_crypt_withlabel();

  ec_keyx();

  asymmetric_ec();
  asymmetric_rsa();
}
