add_smithy_module(
        NAME json
        SOURCES json.c
        DEPENDS stdlib
        LINK_LIBS jansson
)
