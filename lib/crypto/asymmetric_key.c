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

#include "smithy/crypto/asymmetric_key.h"
#include "smithy/crypto/der.h"
#include "smithy/crypto/symmetric_key.h"
#include "smithy/stdlib/memory.h"

#include <time.h>
#include <unistd.h>

int translate_curve(sm_supported_curve curve) {
  switch (curve) {
  case SM_P256: {
    return BR_EC_secp256r1;
  }
  case SM_P384: {
    return BR_EC_secp384r1;
  }
  case SM_P521: {
    return BR_EC_secp521r1;
  }
  default: {
    return 0;
  }
  }
}

// This length is always big enough for the non-asn1 version too
static size_t curve_asn1_signature_length(int curve) {
  switch (curve) {
  case BR_EC_secp256r1: {
    return 72;
  }
  case BR_EC_secp384r1: {
    return 104;
  }
  case BR_EC_secp521r1: {
    return 139;
  }
  default:
    break;
  }
  return 0;
}

static const uint32_t SM_RSA_PUBEXP = 0x10001; // 65537, fermat prime

bool sm_create_ec_keypair(sm_supported_curve curve, br_ec_private_key *priv,
                          br_ec_public_key *pub) {
  sm_buffer kbuf_priv = sm_empty_buffer, kbuf_pub = sm_empty_buffer;
  sm_buffer_resize(&kbuf_priv, BR_EC_KBUF_PRIV_MAX_SIZE);
  sm_buffer_resize(&kbuf_pub, BR_EC_KBUF_PUB_MAX_SIZE);

  br_hmac_drbg_context rng_ctx;
  SM_AUTO(sm_buffer) seed = sm_empty_buffer;
  // TODO: this is for 256 bit security, does it need to be longer?
  sm_buffer_resize(&seed, 48);
  sm_buffer_fill_rand(seed, sm_buffer_begin(seed), sm_buffer_end(seed));
  br_hmac_drbg_init(&rng_ctx, &br_sha512_vtable, sm_buffer_begin(seed),
                    seed.length);

  int c = translate_curve(curve);
  if (c == 0) {
    SM_ERROR("Unknown curve\n");
    return false;
  }

  const br_ec_impl *ec_impl = br_ec_get_default();

  size_t privlen = br_ec_keygen(&rng_ctx.vtable, ec_impl, priv,
                                sm_buffer_begin(kbuf_priv), c);
  if (privlen == 0) {
    SM_ERROR("Unable to generate EC private key for curve ID: %d\n", c);
    return false;
  }
  sm_buffer_resize(&kbuf_priv, privlen);

  size_t publen =
      br_ec_compute_pub(ec_impl, pub, sm_buffer_begin(kbuf_pub), priv);
  if (publen == 0) {
    SM_ERROR("Unable to compute EC public key for curve ID: %d\n", c);
    return false;
  }
  sm_buffer_resize(&kbuf_pub, publen);

  return true;
}

bool sm_create_rsa_keypair(uint16_t bits, br_rsa_private_key *priv,
                           br_rsa_public_key *pub) {
  if (bits < 2048) {
    SM_ERROR("Insecure key size of %u detected, aborting\n", bits);
    return false;
  }

  sm_buffer kbuf_priv = sm_empty_buffer, kbuf_pub = sm_empty_buffer;
  sm_buffer_resize(&kbuf_priv, BR_RSA_KBUF_PRIV_SIZE(bits));
  sm_buffer_resize(&kbuf_pub, BR_RSA_KBUF_PUB_SIZE(bits));

  br_hmac_drbg_context rng_ctx;
  SM_AUTO(sm_buffer) seed = sm_empty_buffer;
  // TODO: this is for 256 bit security, does it need to be longer?
  sm_buffer_resize(&seed, 48);
  sm_buffer_fill_rand(seed, sm_buffer_begin(seed), sm_buffer_end(seed));
  br_hmac_drbg_init(&rng_ctx, &br_sha512_vtable, sm_buffer_begin(seed),
                    seed.length);

  br_rsa_keygen keygen = br_rsa_keygen_get_default();
  uint32_t err = keygen(&rng_ctx.vtable, priv, sm_buffer_begin(kbuf_priv), pub,
                        sm_buffer_begin(kbuf_pub), bits, SM_RSA_PUBEXP);
  if (err != 1) {
    SM_ERROR("Unable to generate RSA keypair of size %u\n", bits);
    return false;
  }

  return true;
}

void sm_ec_keypair_cleanup(const br_ec_private_key *priv,
                           const br_ec_public_key *pub) {
  if (priv) {
    SM_AUTO(sm_buffer) x = sm_buffer_alias(priv->x, priv->xlen);
    (void)x;
  }

  if (pub) {
    SM_AUTO(sm_buffer) q = sm_buffer_alias(pub->q, pub->qlen);
    (void)q;
  }
}

void sm_rsa_keypair_cleanup(const br_rsa_private_key *priv,
                            const br_rsa_public_key *pub) {
  // For both of these keys all the elements are stored in a single buffer,
  // which is why we only have to free the first field.

  if (priv) {
    SM_AUTO(sm_buffer) p = sm_buffer_alias(priv->p, priv->plen);
    (void)p;
  }

  if (pub) {
    SM_AUTO(sm_buffer) n = sm_buffer_alias(pub->n, pub->nlen);
    (void)n;
  }
}

void sm_serialize_ec_privkey(const br_ec_private_key *key, sm_buffer *buf) {
  br_ec_public_key pub;
  SM_AUTO(sm_buffer) kbuf_pub = sm_empty_buffer;
  sm_buffer_resize(&kbuf_pub, BR_EC_KBUF_PUB_MAX_SIZE);
  size_t bytes = br_ec_compute_pub(br_ec_get_default(), &pub,
                                   sm_buffer_begin(kbuf_pub) + 1, key);
  sm_buffer_resize(&kbuf_pub, bytes);

  size_t len = br_encode_ec_raw_der(NULL, key, &pub);
  sm_buffer_reserve(buf, sm_buffer_length(*buf) + len);
  len = br_encode_ec_raw_der(sm_buffer_end(*buf), key, &pub);
  sm_buffer_resize(buf, sm_buffer_length(*buf) + len);
}

void sm_serialize_rsa_privkey(const br_rsa_private_key *key, sm_buffer *buf) {
  // Get the compute modulus
  br_rsa_compute_modulus modulus = br_rsa_compute_modulus_get_default();
  size_t mod_len = modulus(NULL, key);
  SM_ASSERT(mod_len != 0);
  SM_AUTO(sm_buffer) n = sm_empty_buffer;
  sm_buffer_resize(&n, mod_len);
  mod_len = modulus(sm_buffer_begin(n), key);
  SM_ASSERT(mod_len != 0);

  // Get the public exponent in the correct format
  br_rsa_compute_pubexp pubexp = br_rsa_compute_pubexp_get_default();
  uint32_t e = pubexp(key);

  // Get the private exponent from the private key
  br_rsa_compute_privexp privexp = br_rsa_compute_privexp_get_default();
  size_t exp_len = privexp(NULL, key, e);
  SM_AUTO(sm_buffer) d = sm_empty_buffer;
  sm_buffer_resize(&d, exp_len);
  (void)privexp(sm_buffer_begin(d), key, SM_RSA_PUBEXP);

  br_rsa_public_key pub;
  pub.n = sm_buffer_begin(n);
  pub.nlen = n.length;
  pub.e = (uint8_t *)&e;
  pub.elen = 4;

  size_t len =
      br_encode_rsa_raw_der(NULL, key, &pub, sm_buffer_begin(d), d.length);
  sm_buffer_reserve(buf, sm_buffer_length(*buf) + len);
  len = br_encode_rsa_raw_der(sm_buffer_end(*buf), key, &pub,
                              sm_buffer_begin(d), d.length);
  sm_buffer_resize(buf, sm_buffer_length(*buf) + len);
}

static bool der_encode_curve(int curve, sm_der_node *der) {
  switch (curve) {
  case BR_EC_secp256r1: {
    /*
     * secp256r1 OBJECT IDENTIFIER ::= {
     * iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
     * prime(1) 7 }
     */
    sm_der_oid_begin(1, 2, der);
    sm_der_oid_push(840, der);
    sm_der_oid_push(10045, der);
    sm_der_oid_push(3, der);
    sm_der_oid_push(1, der);
    sm_der_oid_push(7, der);
    return true;
  }
  case BR_EC_secp384r1: {
    /*
     * secp384r1 OBJECT IDENTIFIER ::= {
     * iso(1) identified-organization(3) certicom(132) curve(0) 34 }
     */
    sm_der_oid_begin(1, 3, der);
    sm_der_oid_push(132, der);
    sm_der_oid_push(0, der);
    sm_der_oid_push(34, der);
    return true;
  }
  case BR_EC_secp521r1: {
    /*
     * secp521r1 OBJECT IDENTIFIER ::= {
     * iso(1) identified-organization(3) certicom(132) curve(0) 35 }
     */
    sm_der_oid_begin(1, 3, der);
    sm_der_oid_push(132, der);
    sm_der_oid_push(0, der);
    sm_der_oid_push(35, der);
    return true;
  }
  default: {
    SM_ERROR("Unknown or unsupported curve\n");
    return false;
  }
  }
}

static void der_encode_ec_pubkey(const void *k, sm_der_node *root) {
  // These are freed by root when it is cleaned up
  sm_der_node *algorithm_id;
  sm_der_node *algorithm;
  sm_der_node *parameters;
  sm_der_node *pub_key;
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
   */

  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &algorithm_id, root);
  sm_der_alloc(SM_DER_TYPE_OBJECT_IDENTIFIER, &algorithm, algorithm_id);
  /*
   * The algorithm is usually this
   * id-ecPublicKey OBJECT IDENTIFIER ::= {
   *   iso(1) member-body(2) us(840)
   * ansi-X9-62(10045) keyType(2) 1 }
   */
  sm_der_oid_begin(1, 2, algorithm);
  sm_der_oid_push(840, algorithm);
  sm_der_oid_push(10045, algorithm);
  sm_der_oid_push(2, algorithm);
  sm_der_oid_push(1, algorithm);

  /* Then we have to specify the parameters */
  sm_der_alloc(SM_DER_TYPE_OBJECT_IDENTIFIER, &parameters, algorithm_id);

  const br_ec_public_key *key = k;
  SM_ASSERT(der_encode_curve((key)->curve, parameters));

  sm_der_alloc(SM_DER_TYPE_BIT_STRING, &pub_key, root);
  sm_buffer key_alias = sm_buffer_alias((key)->q, (key)->qlen);
  sm_der_encode_buffer(key_alias, pub_key);
}

void sm_serialize_ec_pubkey(const br_ec_public_key *key, sm_buffer *buf) {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);
  der_encode_ec_pubkey(key, &root);
  // And serialize it all
  sm_der_serialize(&root, buf);
}

static void der_encode_rsa_pubkey(const void *k, sm_der_node *root) {
  sm_der_node *algorithm_id;
  sm_der_node *algorithm;
  sm_der_node *parameters;
  sm_der_node *pub_key;
  SM_AUTO(sm_der_node) rsa_pubkey_seq;
  SM_AUTO(sm_der_node) n;
  SM_AUTO(sm_der_node) e;

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
   */

  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &algorithm_id, root);
  sm_der_alloc(SM_DER_TYPE_OBJECT_IDENTIFIER, &algorithm, algorithm_id);

  /*
   * pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
   *                 rsadsi(113549) pkcs(1) 1 }
   *  rsaEncryption OBJECT IDENTIFIER ::=  { pkcs-1 1}
   */
  sm_der_oid_begin(1, 2, algorithm);
  sm_der_oid_push(840, algorithm);
  sm_der_oid_push(113549, algorithm);
  sm_der_oid_push(1, algorithm);
  sm_der_oid_push(1, algorithm);
  sm_der_oid_push(1, algorithm);

  /* Parameters MUST be NULL */
  sm_der_alloc(SM_DER_TYPE_NULL, &parameters, algorithm_id);

  sm_der_alloc(SM_DER_TYPE_BIT_STRING, &pub_key, root);

  /*
   * RSAPublicKey ::= SEQUENCE {
   *      modulus           INTEGER,  -- n
   *      publicExponent    INTEGER   -- e
   *  }
   */
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &rsa_pubkey_seq);

  const br_rsa_public_key *key = k;
  sm_der_add(SM_DER_TYPE_INTEGER, &n, &rsa_pubkey_seq);
  sm_buffer n_alias = sm_buffer_alias((key)->n, (key)->nlen);

  SM_AUTO(sm_buffer) n_buf = sm_empty_buffer;
  if ((sm_buffer_at(n_alias, 0) & 0x80) != 0) {
    /* This is only needed if the high bit is set - it's a positive number
     */
    sm_buffer_push(&n_buf, 0);
  }
  sm_buffer_insert(&n_buf, sm_buffer_end(n_buf), sm_buffer_begin(n_alias),
                   sm_buffer_end(n_alias));
  sm_der_encode_buffer(n_buf, &n);

  sm_der_add(SM_DER_TYPE_INTEGER, &e, &rsa_pubkey_seq);
  sm_buffer e_alias = sm_buffer_alias((key)->e, (key)->elen);
  SM_AUTO(sm_buffer) e_buf = sm_empty_buffer;
  sm_buffer_insert(&e_buf, sm_buffer_end(e_buf), sm_buffer_begin(e_alias),
                   sm_buffer_end(e_alias));
  sm_der_encode_buffer(e_alias, &e);

  SM_AUTO(sm_buffer) pubkey_root_buf = sm_empty_buffer;
  sm_der_serialize(&rsa_pubkey_seq, &pubkey_root_buf);

  // Have to serialize it and then shove it into the public key
  sm_der_encode_buffer(pubkey_root_buf, pub_key);
}

void sm_serialize_rsa_pubkey(const br_rsa_public_key *key, sm_buffer *buf) {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);
  der_encode_rsa_pubkey(key, &root);
  sm_der_serialize(&root, buf);
}

/*
 * Name ::= CHOICE { -- only one possibility for now --
   rdnSequence  RDNSequence }

   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

   RelativeDistinguishedName ::=
     SET SIZE (1..MAX) OF AttributeTypeAndValue

   AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

   AttributeType ::= OBJECT IDENTIFIER

   AttributeValue ::= ANY -- DEFINED BY AttributeType

   DirectoryString ::= CHOICE {
         teletexString           TeletexString (SIZE (1..MAX)),
         printableString         PrintableString (SIZE (1..MAX)),
         universalString         UniversalString (SIZE (1..MAX)),
         utf8String              UTF8String (SIZE (1..MAX)),
         bmpString               BMPString (SIZE (1..MAX)) }
 */

// Appends a name starting from the RelativeDistinguishedName
static void der_append_name(const sm_buffer buf, const char *oid,
                            sm_der_node *parent) {
  sm_der_node *rdn;
  sm_der_node *attr_value_and_type;
  sm_der_node *type;
  sm_der_node *value;
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SET), &rdn, parent);
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &attr_value_and_type,
               rdn);
  sm_der_alloc(SM_DER_TYPE_OBJECT_IDENTIFIER, &type, attr_value_and_type);

  char *end = NULL;
  const char *iter = oid;
  uint8_t first = strtol(iter, &end, 10);
  SM_ASSERT(*end == '.');
  iter = end + 1;
  uint8_t second = strtol(iter, &end, 10);
  SM_ASSERT(*end == '.');
  sm_der_oid_begin(first, second, type);
  do {
    uint8_t n = strtol(iter, &end, 10);
    if (*end == '.')
      ++end;
    iter = end;

    sm_der_oid_push(n, type);
  } while (*end != '\0');

  sm_der_alloc(SM_DER_TYPE_UTF8_STRING, &value, attr_value_and_type);
  sm_der_encode_buffer(buf, value);
}

static void der_ecdsa_with_sha256(sm_der_node *parent) {
  sm_der_node *alg_id_seq;
  sm_der_node *alg_id;

  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &alg_id_seq, parent);
  sm_der_alloc(SM_DER_TYPE_OBJECT_IDENTIFIER, &alg_id, alg_id_seq);
  /*
   * ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
     ecdsa-with-SHA2(3) ecdsa-with-SHA256(2)}
   */
  sm_der_oid_begin(1, 2, alg_id);
  sm_der_oid_push(840, alg_id);
  sm_der_oid_push(10045, alg_id);
  sm_der_oid_push(4, alg_id);
  sm_der_oid_push(3, alg_id);
  sm_der_oid_push(2, alg_id);
}

static void der_sha256_with_rsa(sm_der_node *parent) {
  sm_der_node *alg_id_seq;
  sm_der_node *alg_id;
  sm_der_node *null;

  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &alg_id_seq, parent);
  sm_der_alloc(SM_DER_TYPE_OBJECT_IDENTIFIER, &alg_id, alg_id_seq);
  /*
   * sha256WithRSAEncryption OBJECT IDENTIFIER ::= {iso(1) member-body(2)
   * us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha256WithRSAEncryption(11)}
   */
  sm_der_oid_begin(1, 2, alg_id);
  sm_der_oid_push(840, alg_id);
  sm_der_oid_push(113549, alg_id);
  sm_der_oid_push(1, alg_id);
  sm_der_oid_push(1, alg_id);
  sm_der_oid_push(11, alg_id);

  // For some reason it has a null at the end
  sm_der_alloc(SM_DER_TYPE_NULL, &null, alg_id_seq);
}

/*
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
    Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

    CertificateSerialNumber  ::=  INTEGER

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }

    Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

    Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

    UniqueIdentifier  ::=  BIT STRING

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

    Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
   */
// Up to the subject field
static void der_tbs_cert_preamble(sm_der_node *tbs_cert,
                                  void (*signing_alg)(sm_der_node *)) {
  sm_der_node *zero;
  sm_der_alloc(SM_DER_SEQ_NUMBER(0), &zero, tbs_cert);
  sm_der_node *version;
  sm_der_alloc(SM_DER_TYPE_INTEGER, &version, zero);
  sm_der_encode_integer(2, version);

  sm_der_node *serial_number;
  sm_der_alloc(SM_DER_TYPE_INTEGER, &serial_number, tbs_cert);
  // Self-signed certificate, don't care about the SN
  sm_der_encode_integer(0, serial_number);

  // The signing algorithm for the cert
  signing_alg(tbs_cert);

  // Issuer
  sm_der_node *iss;
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &iss, tbs_cert);
  const sm_buffer namestr = sm_buffer_alias_str("self");
  der_append_name(namestr, "2.5.4.3", iss);

  sm_der_node *valid;
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &valid, tbs_cert);

  sm_der_node *not_before;
  sm_der_alloc(SM_DER_TYPE_GENERALIZED_TIME, &not_before, valid);

  time_t now = time(NULL);
  struct tm gm_now;
  gmtime_r(&now, &gm_now);
  char timestr[18];
  ssize_t written = strftime(timestr, 18, "%Y%m%d%H%M%SZ", &gm_now);
  SM_ASSERT(written > 0);
  sm_buffer nbf = sm_buffer_alias_str(timestr);
  sm_der_encode_buffer(nbf, not_before);

  sm_der_node *not_after;
  sm_der_alloc(SM_DER_TYPE_GENERALIZED_TIME, &not_after, valid);

  ++gm_now.tm_year;
  written = strftime(timestr, 18, "%Y%m%d%H%M%SZ", &gm_now);
  SM_ASSERT(written > 0);
  sm_buffer naf = sm_buffer_alias_str(timestr);
  sm_der_encode_buffer(naf, not_after);

  // Subject
  sm_der_node *subj;
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &subj, tbs_cert);
  der_append_name(namestr, "2.5.4.3", subj);
}

/*
    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier, <- must match TBSCertificate
        signatureValue       BIT STRING  }
  */

bool sm_ec_pubkey_to_cert(const br_ec_private_key *priv,
                          const br_ec_public_key *pub, sm_buffer *buf) {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);

  sm_der_node tbs_cert;
  sm_der_add(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &tbs_cert, &root);

  der_tbs_cert_preamble(&tbs_cert, &der_ecdsa_with_sha256);

  sm_der_node pubkey;
  sm_der_add(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &pubkey, &tbs_cert);
  der_encode_ec_pubkey(pub, &pubkey);

  // algorithm identifier for the top level cert
  der_ecdsa_with_sha256(&root);

  SM_AUTO(sm_buffer) to_sign = sm_empty_buffer;
  sm_der_serialize(&root, &to_sign);

  // Sign it
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, sm_buffer_begin(to_sign), sm_buffer_length(to_sign));
  uint8_t sgn[br_sha256_SIZE];
  br_sha256_out(&ctx, sgn);

  SM_AUTO(sm_buffer) sig = sm_empty_buffer;
  size_t sigsize = curve_asn1_signature_length(priv->curve);
  if (sigsize == 0) {
    SM_ERROR("Unknown curve: %d", priv->curve);
    return false;
  }
  sm_buffer_resize(&sig, sigsize);
  const br_ec_impl *impl = br_ec_get_default();
  br_ecdsa_sign sign = br_ecdsa_sign_asn1_get_default();
  size_t outlen =
      sign(impl, &br_sha256_vtable, sgn, priv, sm_buffer_begin(sig));
  if (outlen == 0) {
    return false;
  }

  // Resize the buffer
  sm_buffer_resize(&sig, outlen);

  sm_der_node signature;
  sm_der_add(SM_DER_TYPE_BIT_STRING, &signature, &root);
  sm_der_encode_buffer(sig, &signature);

  sm_der_serialize(&root, buf);

  return true;
}

bool sm_rsa_pubkey_to_cert(const br_rsa_private_key *priv,
                           const br_rsa_public_key *pub, sm_buffer *buf) {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);

  sm_der_node tbs_cert;
  sm_der_add(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &tbs_cert, &root);

  der_tbs_cert_preamble(&tbs_cert, &der_sha256_with_rsa);

  sm_der_node pubkey;
  sm_der_add(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &pubkey, &tbs_cert);
  der_encode_rsa_pubkey(pub, &pubkey);

  // algorithm identifier for the top level cert
  der_sha256_with_rsa(&root);

  SM_AUTO(sm_buffer) to_sign = sm_empty_buffer;
  sm_der_serialize(&root, &to_sign);

  // Sign it
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, sm_buffer_begin(to_sign), sm_buffer_length(to_sign));
  uint8_t sgn[br_sha256_SIZE];
  br_sha256_out(&ctx, sgn);

  SM_AUTO(sm_buffer) sig = sm_empty_buffer;
  sm_buffer_resize(&sig, (priv->n_bitlen + 7) / 8);

  const br_rsa_pkcs1_sign sign = br_rsa_pkcs1_sign_get_default();
  if (0 == sign(NULL, sgn, br_sha256_SIZE, priv, sm_buffer_begin(sig))) {
    return false;
  }

  sm_der_node signature;
  sm_der_add(SM_DER_TYPE_BIT_STRING, &signature, &root);
  sm_der_encode_buffer(sig, &signature);

  sm_der_serialize(&root, buf);

  return true;
}

/*
 CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
        attributes    [0] Attributes{{ CRIAttributes }}
   }
 */
static void build_cert_request(sm_der_node *parent, const sm_buffer org,
                               const sm_buffer cn, const void *pubkey,
                               void (*der_encode_pubkey)(const void *,
                                                         sm_der_node *)) {
  sm_der_node *cert_request;
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &cert_request, parent);

  sm_der_node *version;
  sm_der_alloc(SM_DER_TYPE_INTEGER, &version, cert_request);
  sm_der_encode_integer(0, version);

  // Subject is me, so do that
  sm_der_node *n;
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &n, cert_request);
  // First is CN
  der_append_name(cn, "2.5.4.3", n);

  // Then Org
  der_append_name(org, "2.5.4.10", n);

  // Now the public key, that's easy
  sm_der_node *pk;
  sm_der_alloc(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &pk, cert_request);
  der_encode_pubkey(pubkey, pk);

  // And we don't have anything in the end field, so just an empty [0]
  sm_der_node *zero;
  sm_der_alloc(SM_DER_SEQ_NUMBER(0), &zero, cert_request);
}

/*
 * CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }
 */

bool sm_ec_get_csr(const br_ec_private_key *priv, const br_ec_public_key *pub,
                   const sm_buffer org, const sm_buffer cn, sm_buffer *pembuf) {

  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);

  // Build the cert request
  build_cert_request(&root, org, cn, (void *)pub, &der_encode_ec_pubkey);

  der_ecdsa_with_sha256(&root);

  SM_AUTO(sm_buffer) to_sign = sm_empty_buffer;
  sm_der_serialize(&root, &to_sign);

  // Sign it
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, sm_buffer_begin(to_sign), sm_buffer_length(to_sign));
  uint8_t sgn[br_sha256_SIZE];
  br_sha256_out(&ctx, sgn);

  SM_AUTO(sm_buffer) sig = sm_empty_buffer;
  size_t sigsize = curve_asn1_signature_length(priv->curve);
  if (sigsize == 0) {
    SM_ERROR("Unknown curve: %d", priv->curve);
    return false;
  }
  sm_buffer_resize(&sig, sigsize);
  const br_ec_impl *impl = br_ec_get_default();
  br_ecdsa_sign sign = br_ecdsa_sign_asn1_get_default();
  size_t outlen =
      sign(impl, &br_sha256_vtable, sgn, priv, sm_buffer_begin(sig));
  if (outlen == 0) {
    return false;
  }

  // Resize the buffer
  sm_buffer_resize(&sig, outlen);

  // Add the signature
  sm_der_node signature;
  sm_der_add(SM_DER_TYPE_BIT_STRING, &signature, &root);
  sm_der_encode_buffer(sig, &signature);

  // And we're done
  sm_der_serialize(&root, pembuf);

  return true;
}

bool sm_rsa_get_csr(const br_rsa_private_key *priv,
                    const br_rsa_public_key *pub, const sm_buffer org,
                    const sm_buffer cn, sm_buffer *pembuf) {
  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);

  // Build the cert request
  build_cert_request(&root, org, cn, pub, &der_encode_rsa_pubkey);

  der_sha256_with_rsa(&root);

  SM_AUTO(sm_buffer) to_sign = sm_empty_buffer;
  sm_der_serialize(&root, &to_sign);

  // Sign it
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, sm_buffer_begin(to_sign), sm_buffer_length(to_sign));
  uint8_t sgn[br_sha256_SIZE];
  br_sha256_out(&ctx, sgn);

  SM_AUTO(sm_buffer) sig = sm_empty_buffer;
  sm_buffer_resize(&sig, (priv->n_bitlen + 7) / 8);

  const br_rsa_pkcs1_sign sign = br_rsa_pkcs1_sign_get_default();
  if (0 == sign(NULL, sgn, br_sha256_SIZE, priv, sm_buffer_begin(sig))) {
    return false;
  }

  // Add the signature
  sm_der_node signature;
  sm_der_add(SM_DER_TYPE_BIT_STRING, &signature, &root);
  sm_der_encode_buffer(sig, &signature);

  sm_der_serialize(&root, pembuf);
  return true;
}

bool sm_ec_keyx(const br_ec_private_key *me, const br_ec_public_key *peer,
                sm_buffer *shared_secret) {
  SM_ASSERT(me->curve == peer->curve);

  const br_ec_impl *impl = br_ec_get_default();
  sm_buffer peer_pubkey = sm_buffer_alias(peer->q, peer->qlen);
  // Use `tmp` as a buffer that we can write the result of the multiplication
  // into. We want it gone when this scope ends.
  SM_AUTO(sm_buffer) tmp = sm_buffer_clone(peer_pubkey);

  // ECDH is literally just multiplying the two points together (openssl
  // makes this super complicated)
  uint32_t mulres = impl->mul(sm_buffer_begin(tmp), sm_buffer_length(tmp),
                              me->x, me->xlen, me->curve);

  // Then we just grab the x coordinate (NIST SP800-56A r3)
  size_t xlen = 0;
  size_t xoff = impl->xoff(me->curve, &xlen);
  memmove(sm_buffer_begin(tmp), sm_buffer_begin(tmp) + xoff, xlen);
  sm_buffer_resize(&tmp, xlen);

  // The integer to bytes conversion is just ensuring it's big-endian and
  // padded to 8 bits, which we already have.

  // Then we take the SHA256 of this thing to get a shared secret we can use.
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, sm_buffer_begin(tmp), sm_buffer_length(tmp));

  sm_buffer_resize(shared_secret, br_sha256_SIZE);
  br_sha256_out(&ctx, sm_buffer_begin(*shared_secret));

  return (mulres == 1);
}

bool sm_rsa_encrypt(const br_rsa_public_key *pub, const sm_buffer buf,
                    const sm_buffer label, sm_buffer *ciphertext) {
  // Before doing anything, check that the message is small enough to be
  // encrypted effectively. The standard says:
  //   mLen <= k - 2*hLen - 2
  //   mLen == message length in octets (bytes)
  //   k    == rsa modulus length in octets (bytes)
  //   hLen == hash function output length in octets (bytes)
  // Since we use SHA256 here, hLen == 32.
  if (buf.length > (pub->nlen - 2 * 32 - 2)) {
    SM_ERROR("Message was too long, got %zu bytes but cannot encrypt more than "
             "%zu bytes\n",
             buf.length, (pub->nlen - 2 * 32 - 2));
    return false;
  }

  br_rsa_oaep_encrypt enc = br_rsa_oaep_encrypt_get_default();

  br_hmac_drbg_context rng_ctx;
  SM_AUTO(sm_buffer) seed = sm_empty_buffer;

  // TODO: this is for 256 bit security, does it need to be longer?
  sm_buffer_resize(&seed, 48);
  sm_buffer_fill_rand(seed, sm_buffer_begin(seed), sm_buffer_end(seed));
  br_hmac_drbg_init(&rng_ctx, &br_sha512_vtable, sm_buffer_begin(seed),
                    seed.length);

  // The buffer must be exactly the size of the modulus.
  sm_buffer_resize(ciphertext, pub->nlen);

  size_t ciphertext_bytes =
      enc(&rng_ctx.vtable, &br_sha256_vtable, label.data, label.length, pub,
          ciphertext->data, ciphertext->length, buf.data, buf.length);
  if (ciphertext_bytes == 0) {
    SM_ERROR("Encrypting the message failed\n");
    return false;
  }

  // Truncate to the actual number of bytes needed.
  sm_buffer_resize(ciphertext, ciphertext_bytes);
  return true;
}

bool sm_rsa_decrypt(const br_rsa_private_key *priv, sm_buffer *crypt,
                    const sm_buffer label) {
  if (crypt->length != (priv->n_bitlen / 8)) {
    SM_ERROR("Message cannot be an RSA encrypted message.\n");
    return false;
  }

  br_rsa_oaep_decrypt dec = br_rsa_oaep_decrypt_get_default();

  size_t len = crypt->length;
  if (0 == dec(&br_sha256_vtable, label.data, label.length, priv, crypt->data,
               &len)) {
    SM_ERROR("Decrypting the message failed\n");
    return false;
  }

  // Resize the buffer to the message length.
  sm_buffer_resize(crypt, len);
  return true;
}

//=====-----------------------------------------------------------------=====//
// Type-generic Asymmetric Encrypt/Decrypt
//=====-----------------------------------------------------------------=====//

bool sm_create_asymmetric_keypair(uint16_t bits_or_curve,
                                  sm_asymmetric_private_key *priv,
                                  sm_asymmetric_public_key *pub) {
  bool is_ec = bits_or_curve < 2048;
  if (is_ec) {
    priv->kind = BR_KEYTYPE_EC;
    pub->kind = BR_KEYTYPE_EC;
    return sm_create_ec_keypair((sm_supported_curve)bits_or_curve, &priv->ec,
                                &pub->ec);
  }

  priv->kind = BR_KEYTYPE_RSA;
  pub->kind = BR_KEYTYPE_RSA;
  return sm_create_rsa_keypair(bits_or_curve, &priv->rsa, &pub->rsa);
}

bool sm_asymmetric_encrypt(sm_asymmetric_private_key *me,
                           sm_asymmetric_public_key *peer,
                           const sm_buffer plaintext, sm_buffer *ciphertext,
                           sm_buffer *aad) {
  if (me->kind != peer->kind) {
    SM_ERROR("Key kinds did not match, cannot proceed.\n");
    return false;
  }

  // Set up the buffer we'll use to store the symmetric key bytes we're going to
  // use.
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;

  // Construct an AAD that contains:
  //  - The salt for the PBKDF, or the encrypted symmetric key.
  //  - The IV for the symmetric encryption
  // The format is DER: SEQ(OCTET_STRING, OCTET_STRING)

  SM_AUTO(sm_der_node) root;
  sm_der_begin(SM_DER_CONSTRUCTED(SM_DER_TYPE_SEQUENCE), &root);

  SM_AUTO(sm_der_node) first_node;
  sm_der_add(SM_DER_TYPE_OCTET_STRING, &first_node, &root);

  // If the key kind is EC, compute a shared secret and use that to construct a
  // symmetric key to use for encryption.
  if (peer->kind == BR_KEYTYPE_EC) {
    SM_AUTO(sm_buffer) shared_secret = sm_empty_buffer;
    if (!sm_ec_keyx(&me->ec, &peer->ec, &shared_secret)) {
      SM_ERROR("Computing the shared secret failed.\n");
      return false;
    }

    // Use a PBKDF on the shared secret to ensure it's valid to use as an
    // encryption key.
    SM_AUTO(sm_buffer) salt = sm_empty_buffer;
    sm_keybytes_from_password(shared_secret, 10000, SM_CHACHA20_POLY1305, &salt,
                              &keybytes);

    // The first node contains the salt, in this case.
    sm_der_encode_buffer(salt, &first_node);
  } else if (peer->kind == BR_KEYTYPE_RSA) {
    // Create a random key using the CSPRNG.
    sm_buffer_resize(&keybytes, 32);
    sm_buffer_fill_rand(keybytes, sm_buffer_begin(keybytes),
                        sm_buffer_end(keybytes));

    // Encrypt this key with the RSA key of the recipient.
    SM_AUTO(sm_buffer) encrypted_key = sm_empty_buffer;
    sm_rsa_encrypt(&peer->rsa, keybytes, sm_buffer_alias_str("encryption_key"),
                   &encrypted_key);

    // The first node contains the encrypted key, in this case.
    sm_der_encode_buffer(encrypted_key, &first_node);
  } else {
    SM_ERROR("Unknown key type\n");
    return false;
  }

  sm_symmetric_key key;
  if (!sm_symmetric_key_init(&key, SM_CHACHA20_POLY1305, keybytes)) {
    SM_ERROR("Failed to initialize the symmetric key.\n");
    return false;
  }

  // Symmetric encryption always takes an IV.
  SM_AUTO(sm_buffer) iv = sm_empty_buffer;
  sm_generate_iv(&key, &iv);

  SM_AUTO(sm_der_node) iv_node;
  sm_der_add(SM_DER_TYPE_OCTET_STRING, &iv_node, &root);
  sm_der_encode_buffer(iv, &iv_node);

  SM_AUTO(sm_buffer) aad_buf = sm_empty_buffer;
  sm_der_serialize(&root, &aad_buf);

  // Now we have to add the AAD to the buffer provided by the user. Add it at
  // the beginning, so that the DER parser will pull it out - DER is
  // self-delimiting.
  uint64_t bufferlen = aad_buf.length;
  // Insert the length first.
  sm_buffer_insert(aad, sm_buffer_begin(*aad), (uint8_t *)&bufferlen,
                   (uint8_t *)&bufferlen + sizeof(uint64_t));
  // Then insert the DER encoded data after that.
  sm_buffer_insert(aad, sm_buffer_begin(*aad) + sizeof(uint64_t),
                   sm_buffer_begin(aad_buf), sm_buffer_end(aad_buf));

  // Copy the plaintext into the ciphertext - symmetric encryption happens
  // in-place.
  sm_buffer_copy(plaintext, ciphertext);

  // Now we can encrypt with the full AAD buffer.
  sm_symmetric_encrypt(&key, ciphertext, *aad, iv);

  return true;
}

bool sm_asymmetric_decrypt(sm_asymmetric_private_key *me,
                           sm_asymmetric_public_key *peer,
                           const sm_buffer ciphertext, sm_buffer *aad,
                           sm_buffer *plaintext) {
  if (me->kind != peer->kind) {
    SM_ERROR("Key kinds did not match, cannot proceed.\n");
    return false;
  }

  // Pull the DER encoded salt and IV from the AAD buffer.
  uint64_t der_len = 0;
  sm_memcpy(&der_len, sm_buffer_begin(*aad), sizeof(uint64_t));
  // This is the total length of the DER prefix for the AAD buffer. Use that to
  // pull out the original aad buffer and the DER.
  size_t der_prefix_len = sizeof(uint64_t) + der_len;
  sm_buffer original_aad_buffer =
      sm_buffer_alias(aad->data + der_prefix_len, aad->length - der_prefix_len);
  sm_buffer der = sm_buffer_alias(aad->data + sizeof(uint64_t), der_len);

  SM_AUTO(sm_der_node) root;
  sm_der_deserialize(der, &root);

  sm_der_node *first_node = sm_der_get_child(&root, 0);
  SM_AUTO(sm_buffer) keybytes = sm_empty_buffer;
  if (me->kind == BR_KEYTYPE_EC) {
    // The first node contains the salt in this case.
    sm_buffer salt = first_node->data;

    // Compute a shared secret and decrypt with that.
    SM_AUTO(sm_buffer) shared_secret = sm_empty_buffer;
    if (!sm_ec_keyx(&me->ec, &peer->ec, &shared_secret)) {
      SM_ERROR("Computing the shared secret failed.\n");
      return false;
    }

    // Use a PBKDF on the shared secret to ensure it's valid to use as an
    // encryption key.
    sm_keybytes_from_password(shared_secret, 10000, SM_CHACHA20_POLY1305, &salt,
                              &keybytes);
  } else if (me->kind == BR_KEYTYPE_RSA) {
    // The first node is the encrypted symmetric key. Decrypt it into
    // `keybytes`.
    sm_buffer_copy(first_node->data, &keybytes);
    sm_rsa_decrypt(&me->rsa, &keybytes, sm_buffer_alias_str("encryption_key"));
  } else {
    SM_ERROR("Unknown key type\n");
    return false;
  }

  sm_symmetric_key key;
  if (!sm_symmetric_key_init(&key, SM_CHACHA20_POLY1305, keybytes)) {
    SM_ERROR("Failed to initialize the symmetric key.\n");
    return false;
  }

  sm_der_node *iv_node = sm_der_get_child(&root, 1);
  sm_buffer iv = iv_node->data;

  // Copy the ciphertext into the plaintext - symmetric encryption happens
  // in-place.
  sm_buffer_copy(ciphertext, plaintext);

  if (!sm_symmetric_decrypt(&key, plaintext, *aad, iv)) {
    SM_ERROR("Symmetric decryption failed.\n");
    return false;
  }

  // Copy the original AAD out of the aad buffer, clear it out, and re-insert
  // it. Because the DER-encoded stuff is at the beginning, there's not really a
  // good way to drop it.
  SM_AUTO(sm_buffer) original_aad = sm_buffer_clone(original_aad_buffer);
  sm_buffer_clear(aad);
  sm_buffer_copy(original_aad, aad);

  return true;
}
