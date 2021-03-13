include(CheckSymbolExists)

find_package(Threads)
if (NOT ${Threads_FOUND})
    set(SM_BUILD_THREADS OFF CACHE BOOL "Unable to find threads")
endif()

set(THREADS_PREFER_PTHREAD_FLAG TRUE)

add_smithy_module(
        NAME threads

        SOURCES
        mutex.c
        semaphore.c
        thread_pool.c

        DEPENDS
        stdlib

        DEFINITIONS
        SMITHY_USE_POSIX=$<BOOL:${Threads_FOUND}>

        LINK_LIBS Threads::Threads
)
