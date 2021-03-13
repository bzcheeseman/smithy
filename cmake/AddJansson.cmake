if (NOT __SMITHY_ADD_JANSSON_INCLUDED)
    set(__SMITHY_ADD_JANSSON_INCLUDED TRUE)

    include(FetchContent)

    FetchContent_Declare(jansson
            GIT_REPOSITORY   https://github.com/akheron/jansson.git
            GIT_TAG          v2.13.1
            )

    set(JANSSON_BUILD_DOCS OFF CACHE BOOL "Turn off jansson extras")
    set(JANSSON_EXAMPLES OFF CACHE BOOL "Turn off jansson extras")
    set(JANSSON_WITHOUT_TESTS ON CACHE BOOL "Turn off jansson extras")
    set(JANSSON_INSTALL OFF CACHE BOOL "Turn off jansson extras")
    FetchContent_GetProperties(jansson)
    FetchContent_MakeAvailable(jansson)

    target_include_directories(jansson PUBLIC $<BUILD_INTERFACE:${jansson_BINARY_DIR}/include>)
endif(NOT __SMITHY_ADD_JANSSON_INCLUDED)