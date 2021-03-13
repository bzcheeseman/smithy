function(smithy_module_name outvar name)
    set(${outvar} smithy-${name} PARENT_SCOPE)
endfunction()

function(add_smithy_module)
    set(options "")
    set(single_value_options NAME)
    set(multi_value_options SOURCES DEPENDS DEFINITIONS LINK_LIBS CFLAGS)
    cmake_parse_arguments(ADD_SMITHY_MODULE "${options}" "${single_value_options}" "${multi_value_options}" ${ARGN})

    if (NOT ADD_SMITHY_MODULE_NAME)
        message(FATAL_ERROR "Must define a name for a smithy module")
    endif ()

    smithy_module_name(libname ${ADD_SMITHY_MODULE_NAME})
    add_library(${libname} OBJECT ${ADD_SMITHY_MODULE_SOURCES})

    if (ADD_SMITHY_MODULE_CFLAGS)
        target_compile_options(${libname} PRIVATE ${ADD_SMITHY_MODULE_CFLAGS})
    endif ()

    if (ADD_SMITHY_MODULE_DEPENDS)
        foreach (dep ${ADD_SMITHY_MODULE_DEPENDS})
            smithy_module_name(depname ${dep})
            target_link_libraries(${libname} PUBLIC ${depname})
        endforeach ()
    endif ()

    if (ADD_SMITHY_MODULE_DEFINITIONS)
        foreach (def ${ADD_SMITHY_MODULE_DEFINITIONS})
            target_compile_definitions(${libname} PRIVATE ${def})
        endforeach ()
    endif ()

    if (ADD_SMITHY_MODULE_LINK_LIBS)
        foreach (lib ${ADD_SMITHY_MODULE_LINK_LIBS})
            target_link_libraries(${libname} PRIVATE ${lib})
        endforeach ()
    endif ()

    target_include_directories(${libname} PUBLIC ${PROJECT_SOURCE_DIR}/include)
    if ((CMAKE_BUILD_TYPE MATCHES RELEASE) OR (CMAKE_BUILD_TYPE MATCHES Release))
        target_compile_options(${libname} PUBLIC -flto)
        target_link_options(${libname} PUBLIC -flto)
    endif ()
endfunction()

if (${SM_BUILD_STDLIB})
    add_subdirectory(stdlib)
endif ()

if (${SM_BUILD_CACHE})
    add_subdirectory(cache)
endif ()

if (${SM_BUILD_CRYPTO})
    add_subdirectory(crypto)
endif ()

if (${SM_BUILD_JSON})
    add_subdirectory(json)
endif ()

if (${SM_BUILD_PARSER})
    add_subdirectory(parser)
endif ()

if (${SM_BUILD_THREADS})
    add_subdirectory(threads)
endif ()

if (${SM_BUILD_AUTHN})
    add_subdirectory(authn)
endif ()


add_library(smithy STATIC
        $<$<BOOL:${SM_BUILD_AUTHN}>:$<TARGET_OBJECTS:smithy-authn>>
        $<$<BOOL:${SM_BUILD_CACHE}>:$<TARGET_OBJECTS:smithy-cache>>
        $<$<BOOL:${SM_BUILD_CRYPTO}>:$<TARGET_OBJECTS:smithy-crypto>>
        $<$<BOOL:${SM_BUILD_JSON}>:$<TARGET_OBJECTS:smithy-json>>
        $<$<BOOL:${SM_BUILD_PARSER}>:$<TARGET_OBJECTS:smithy-parser>>
        $<$<BOOL:${SM_BUILD_THREADS}>:$<TARGET_OBJECTS:smithy-threads>>
        $<$<BOOL:${SM_BUILD_STDLIB}>:$<TARGET_OBJECTS:smithy-stdlib>>
        )

if (USE_ASAN)
    target_compile_options(smithy PUBLIC -fsanitize=address,undefined)
    target_link_libraries(smithy PUBLIC -fsanitize=address,undefined)
endif (USE_ASAN)

if ((CMAKE_BUILD_TYPE MATCHES RELEASE) OR (CMAKE_BUILD_TYPE MATCHES Release))
    target_compile_definitions(smithy PUBLIC -DSM_MINIMUM_LOG=kINFO)
    # TODO: adding this here causes segfaults, why?
    # target_compile_options(smithy PUBLIC -flto)
    # target_link_options(smithy PUBLIC -flto)
endif ()

target_link_libraries(smithy PUBLIC jansson bearssl)
target_include_directories(smithy PUBLIC ${PROJECT_SOURCE_DIR}/include)
