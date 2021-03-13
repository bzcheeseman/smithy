if (NOT __SMITHY_CLANG_ANALYZER_INCLUDED)
    set(__SMITHY_CLANG_ANALYZER_INCLUDED TRUE)

    find_program(CLANG_ANALYZER "scan-build" HINTS ${LLVM_BIN_PATH})
    if (CLANG_ANALYZER)
        message(STATUS "Found scan-build: ${CLANG_ANALYZER}")
        configure_file(${CMAKE_SOURCE_DIR}/cmake/static_analysis.sh.in ${CMAKE_BINARY_DIR}/static_analysis.sh @ONLY)
        add_custom_target(
                clang-analyzer
                COMMAND chmod +x ${CMAKE_BINARY_DIR}/static_analysis.sh
                COMMAND ${CMAKE_BINARY_DIR}/static_analysis.sh
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    else ()
        message(STATUS "Unable to find scan-build")
    endif ()
endif (NOT __SMITHY_CLANG_ANALYZER_INCLUDED)