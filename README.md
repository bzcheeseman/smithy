# smithy

C utility library with several modules. Intended to work well for and with embedded systems.

Uses clang-analyzer for static analysis, and ASAN for memory safety. All modules on `main` must be ASAN-clean

## Using smithy

smithy is a CMake based project, so it's easiest to use from another CMake project. Simply use the following CMake code
in a file like
`AddSmithy.cmake`

```cmake
if (NOT __ADD_SMITHY_INCLUDED)
  set(__ADD_SMITHY_INCLUDED TRUE)

  include(FetchContent)
  FetchContent_Declare(smithy
    GIT_REPOSITORY https://github.com/bzcheeseman/smithy.git
    GIT_TAG <hash/tag/branch>
    )
  FetchContent_GetProperties(smithy)
  FetchContent_MakeAvailable(smithy)

  message(STATUS "Smithy at ${smithy_SOURCE_DIR}")
endif (NOT __ADD_SMITHY_INCLUDED)
```

And somewhere in your main CMakeLists.txt file you'll need to

```cmake
include(path/to/AddSmithy.cmake)
```

All modules are on by default, they can be turned off by passing the appropriate flags to CMake (listed in each section)

# List of Modules
1. [`authn`](#authn)
2. [`cache`](#cache)
3. [`crypto`](#crypto)
4. [`json`](#json)
5. [`parser`](#parser)
6. [`stdlib`](#stdlib)
7. [`elf`](#elf)
8. [`threads`](#threads)

## `authn`

Provides JWT support.

Turn off with `-DSM_BUILD_AUTHN=OFF`.

Requires `crypto`, `json` and `stdlib` modules.

## `cache`

Provides support for a write-through key-value cache.

Turn off with `-DSM_BUILD_CACHE=OFF`.

Requires `stdlib` module.

## `crypto`

Provides cryptography support using `bearssl`. Provides asymmetric encryption, symmetric encryption (authenticated and
streaming).

Turn off with `-DSM_BUILD_CRYPTO=OFF`.

Requires `stdlib` module.

## `json`

Provides json support using `jansson`. Essentially just a wrapper to make it easier to use `sm_buffer` objects with JSON
constructs.

Turn off with `-DSM_BUILD_JSON=OFF`.

Requires `stdlib` module.

## `parser`

Provides a simple and generic parser/lexer for simple languages. Useful for defining config file formats or simple DSLs.

Turn off with `-DSM_BUILD_PARSER=OFF`.

Requires `stdlib` module.

## `stdlib`

Provides stdlib support - eventually should be enough to build most of smithy without libc.

Turn off with `-DSM_BUILD_STDLIB=OFF`.

Turning this off will turn off all of smithy, so I don't recommend doing this.

## `elf`

Provides a simple ELF loader and (someday) linker.

Turn off with `-DSM_BUILD_ELF=OFF`.

Requires `stdlib` module.

## `threads`

Provides mutex, semaphore, concurrent queue, and thread pool support. The thread pool is extremely simple but
fairly effective.

Turn off with `-DSM_BUILD_THREADS=OFF`

TODO: make threads fully capable of running with no OS?
TODO: add select/poll functionality

### References
- Useful bit-twiddling tricks: https://github.com/electronicarts/EAStdC/blob/master/include/EAStdC/EABitTricks.h
- ELF file format: http://www.skyfree.org/linux/references/ELF_Format.pdf
