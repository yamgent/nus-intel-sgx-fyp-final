# The building constants and logic are adapted from Intel's sample code:
#
# https://github.com/intel/linux-sgx/blob/1ccf25b64a/SampleCode/RemoteAttestation/Makefile

include(${CMAKE_CURRENT_LIST_DIR}/SgxCommon.cmake)

########### App Variables Setup ###########

set(APP_INCLUDE_PATHS "Include" "App" "${SGX_SDK}/include"
        "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")

set(APP_CPP_FLAGS "${SGX_COMMON_CFLAGS}" "-fPIC" "-Wno-attributes"
        "-DDEBUG" "-UNDEBUG" "-UEDEBUG" "-std=c++11")

set(APP_LINK_FLAGS "${SGX_COMMON_CFLAGS}" "-L${SGX_LIBRARY_PATH}" "-l${URTS_LIBRARY_NAME}" "-lpthread"
        "-l${UAE_SERVICE_LIBRARY_NAME}" "-l${UKEY_EXCHANGE_LIBRARY_NAME}")

########### App Building Procedures ###########

# build a proper sgx application with bridge to an enclave
function(add_sgx_app)
    cmake_parse_arguments(ADD_SGX_APP "" "TARGET" "APP_CPP_FILES;LINK_ENCLAVES" ${ARGN})

    set(PATH_LINK_ENCLAVE_U_C "")
    foreach(link_enclave_var ${ADD_SGX_APP_LINK_ENCLAVES})
        get_target_property(temp_var ${link_enclave_var} ENCLAVE_UNTRUSTED_SOURCE)
        set(PATH_LINK_ENCLAVE_U_C ${PATH_LINK_ENCLAVE_U_C} ${temp_var})
    endforeach()   

    # generate the exectuable file (app.bin)
    add_executable(${ADD_SGX_APP_TARGET} ${ADD_SGX_APP_APP_CPP_FILES} ${PATH_LINK_ENCLAVE_U_C})
    set_target_properties(${ADD_SGX_APP_TARGET} PROPERTIES COMPILE_FLAGS ${APP_CPP_FLAGS})
    target_include_directories(${ADD_SGX_APP_TARGET} PRIVATE ${APP_INCLUDE_PATHS})
    target_link_libraries(${ADD_SGX_APP_TARGET} ${APP_LINK_FLAGS})
    target_compile_definitions(${ADD_SGX_APP_TARGET} PRIVATE USING_SGX)
endfunction()
