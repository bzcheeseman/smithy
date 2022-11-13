include(CheckSymbolExists)

option(SM_NO_STDLIB "Build without the C standard library" OFF)
if (SM_NO_STDLIB)
    message(FATAL_ERROR "Building without the C standard library isn't supported yet")
endif ()

# There are 2 ways to customize the smithy alloc path:
#  1. override calloc/free
#  2. completely override the alloc.h interface with a different file

set(SM_CALLOC_IMPL
        "calloc"
        CACHE STRING
        "Set the function called to allocate memory. Expects calloc, NOT malloc.")
set(SM_FREE_IMPL
        "free"
        CACHE STRING
        "Set the function called to free memory.")

set(SM_ALLOC_OVERRIDE
        "${CMAKE_CURRENT_SOURCE_DIR}/posix/alloc.c"
        CACHE FILEPATH
        "Fully override the implementation of the interface defined in smithy/stdlib/alloc.h")

option(SM_STATIC_ALLOC "Build smithy with a statically managed allocator." ON)
if (SM_STATIC_ALLOC)
    if (NOT SM_STATIC_HEAP_BYTES)
        set(SM_STATIC_HEAP_BYTES "67108864") # 64M default heap
    endif ()
    add_definitions(-DSM_STATIC_HEAP_BYTES=${SM_STATIC_HEAP_BYTES})
    set(SM_ALLOC_OVERRIDE "${CMAKE_CURRENT_SOURCE_DIR}/static/alloc.c")
endif ()

set(SM_RANDOM_BUF
        "arc4random_buf"
        CACHE STRING
        "Symbol to use to get cryptographically-secure randomness into a buffer.")

set(SM_FILESYSTEM_IMPL
        "${CMAKE_CURRENT_SOURCE_DIR}/posix/filesystem.c"
        CACHE FILEPATH
        "Path to a C source file that defines the interface in smithy/stdlib/filesystem.h")

# Helper to decide on linux platforms if we need to include libbsd
if (${SM_RANDOM_BUF} STREQUAL "arc4random_buf")
    check_symbol_exists(arc4random_buf stdlib.h HAS_BSD)
else ()
    set(HAS_BSD TRUE)
endif ()

set(SRC
        # Override-able files
        ${SM_ALLOC_OVERRIDE}
        ${SM_FILESYSTEM_IMPL}
        # The rest of the stdlib module depends on those files
        b64.c
        buffer.c
        hash_table.c
        linked_list.c
        logging.c
        memory.c
        queue.c
        tree.c
        twine.c)

add_smithy_module(
        NAME stdlib
        SOURCES ${SRC}
        DEFINITIONS
        SM_CALLOC_IMPL=${SM_CALLOC_IMPL}
        SM_FREE_IMPL=${SM_FREE_IMPL}
        SM_RANDOM_BUF=${SM_RANDOM_BUF}
        $<$<BOOL:$<NOT:${HAS_BSD}>>:SM_NEEDS_BSD>
        LINK_LIBS
        $<$<BOOL:$<NOT:${HAS_BSD}>>:bsd>
)
