add_smithy_module(
  NAME parser

  SOURCES
  diagnostic_engine.c
  lexer.c
  parser.c
  source_manager.c

  DEPENDS stdlib
)
