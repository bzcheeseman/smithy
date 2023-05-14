add_smithy_module(
  NAME authn
  SOURCES jwt.c
  DEPENDS stdlib json crypto
  LINK_LIBS jansson bearssl
)
