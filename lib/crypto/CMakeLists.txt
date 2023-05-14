set(SRC
  asymmetric_key.c
  cert_chain.c
  der.c
  ec_sign.c
  ec_verify.c
  rsa_sign.c
  rsa_verify.c
  sign_engine.c
  stream.c
  symmetric_key.c
  trust_store.c
  verify_engine.c)

add_smithy_module(
  NAME crypto
  SOURCES ${SRC}
  DEPENDS stdlib
  LINK_LIBS bearssl
)
