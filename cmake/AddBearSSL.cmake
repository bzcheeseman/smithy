if (NOT __SMITHY_ADD_BEARSSL_INCLUDED)
    set(__SMITHY_ADD_BEARSSL_INCLUDED TRUE)

    include(FetchContent)

    FetchContent_Declare(bearssl-download
            GIT_REPOSITORY https://www.bearssl.org/git/BearSSL
            GIT_TAG b2ec2030e40acf5e9e4cd0f2669aacb27eadb540 # use most recent commit
    )
    FetchContent_GetProperties(bearssl-download)
    FetchContent_MakeAvailable(bearssl-download)

    find_program(MAKE_EXE NAMES gmake nmake make)
    add_custom_target(bearssl-build
            COMMAND ${MAKE_EXE}
            WORKING_DIRECTORY ${bearssl-download_SOURCE_DIR}
            BYPRODUCTS ${bearssl-download_SOURCE_DIR}/build/libbearssl.a
    )

    add_library(bearssl STATIC IMPORTED)
    add_dependencies(bearssl bearssl-build)
    set_target_properties(bearssl PROPERTIES IMPORTED_LOCATION ${bearssl-download_SOURCE_DIR}/build/libbearssl.a)
    target_include_directories(bearssl INTERFACE ${bearssl-download_SOURCE_DIR}/inc)
endif (NOT __SMITHY_ADD_BEARSSL_INCLUDED)