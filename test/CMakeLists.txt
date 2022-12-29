add_custom_target(check-smithy COMMAND ${CMAKE_CTEST_COMMAND} -j --schedule-random -V)

file(GLOB HELPERS ${CMAKE_CURRENT_SOURCE_DIR}/utils/*)

option(SM_SLOW_TESTS OFF "Build/run slow tests")

function(add_ctest test_name)
    add_executable(${test_name} EXCLUDE_FROM_ALL ${HELPERS} ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)
    # Inherits -fsanitize=address from top target
    target_compile_options(${test_name} PUBLIC -g -O0 -fPIC -fstack-protector-strong -Wall -fsanitize=address)
    target_compile_definitions(${test_name} PRIVATE -DSMITHY_TEST_RESOURCE_PATH=${CMAKE_CURRENT_SOURCE_DIR}/resources)
    if (${SM_SLOW_TESTS})
        target_compile_definitions(${test_name} PRIVATE -DSM_SLOW_TESTS)
    endif ()

    target_link_libraries(${test_name} PRIVATE ${ARGN})
    target_link_libraries(${test_name} PRIVATE -fsanitize=address)

    add_test(NAME ${test_name} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${test_name})
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 5)
    set_tests_properties(${test_name} PROPERTIES ENVIRONMENT ASAN_OPTIONS=detect_leaks=1)
    add_dependencies(check-smithy ${test_name})
endfunction(add_ctest)

function(add_fuzz_test test_name)
    add_executable(${test_name} EXCLUDE_FROM_ALL ${HELPERS} ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c)
    # Inherits -fsanitize=address from top target
    target_compile_options(${test_name} PUBLIC -g -O0 -fPIC -fstack-protector-strong -Wall -fsanitize=fuzzer,address)
    target_compile_definitions(${test_name} PRIVATE -DSMITHY_TEST_RESOURCE_PATH=${CMAKE_CURRENT_SOURCE_DIR}/resources)

    target_link_libraries(${test_name} PRIVATE ${ARGN})
    target_link_libraries(${test_name} PRIVATE -fsanitize=fuzzer,address)
endfunction(add_fuzz_test)

if (${SM_BUILD_CRYPTO})
    add_ctest(test_asymmetric_key smithy)
    add_ctest(test_certificate_chain smithy)
    add_ctest(test_der smithy)
    add_ctest(test_stream_crypto smithy)
    add_ctest(test_symmetric_key smithy)
    add_fuzz_test(fuzz_der smithy)
endif ()

if (${SM_BUILD_STDLIB})
    add_ctest(test_buffer smithy)
    add_ctest(test_hash_table smithy)
    add_ctest(test_b64 smithy)
    add_ctest(test_queue smithy)
    add_ctest(test_linked_list smithy)
    add_ctest(test_twine smithy)
    add_ctest(test_tree smithy)
    add_fuzz_test(fuzz_b64 smithy)
endif ()

if (${SM_BUILD_CACHE})
    add_ctest(test_cache smithy)
endif ()

if (${SM_BUILD_AUTHN})
    add_ctest(test_jwt smithy)
endif ()

if (${SM_BUILD_PARSER})
    add_ctest(test_lexer smithy)
    add_ctest(test_parser smithy)
endif ()

if (${SM_BUILD_THREADS})
    add_ctest(test_thread_pool smithy)
endif ()

