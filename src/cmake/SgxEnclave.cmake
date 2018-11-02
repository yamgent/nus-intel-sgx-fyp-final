# The building constants and logic are adapted from Intel's sample code:
#
# https://github.com/intel/linux-sgx/blob/1ccf25b64a/SampleCode/RemoteAttestation/Makefile

include(${CMAKE_CURRENT_LIST_DIR}/SgxCommon.cmake)

########### Enclave Variables Setup ###########

set(ENCLAVE_INCLUDE_DIRECTORIES "Include" "Enclave" "${SGX_SDK}/include" "${SGX_SDK}/include/tlibc" "${SGX_SDK}/include/libcxx"
        "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
set(ENCLAVE_CPP_FLAGS "${SGX_COMMON_CFLAGS}" "-nostdinc" "-fvisibility=hidden" "-fpie" "-ffunction-sections" "-fdata-sections"
        "-fstack-protector-strong" "-std=c++11" "-nostdinc++")

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
set(ENCLAVE_LINK_FLAGS "${SGX_COMMON_CFLAGS}" "-Wl,--no-undefined" "-nostdlib" "-nodefaultlibs" "-nostartfiles"
        "-L${SGX_LIBRARY_PATH}"
        "-Wl,--whole-archive" "-l${TRTS_LIBRARY_NAME}" "-Wl,--no-whole-archive"
        "-Wl,--start-group" "-lsgx_tstdc" "-lsgx_tcxx" 
                "-l${CRYPTO_LIBRARY_NAME}" "-l${SERVICE_LIBRARY_NAME}" "-l${TKEY_EXCHANGE_LIBRARY_NAME}" "-Wl,--end-group"
        "-Wl,-Bstatic" "-Wl,-Bsymbolic" "-Wl,--no-undefined"
        "-Wl,-pie,-eenclave_entry" "-Wl,--export-dynamic"
        "-Wl,--defsym,__ImageBase=0" "-Wl,--gc-sections")

########### Enclave Building Procedures ###########

# build a proper sgx enclave
#
# requires the following file inside the 'ENCLAVE_DIR' for method to work:
#   - <TARGET>_private.pem
#   - <TARGET>.config.xml
#   - <TARGET>.edl
#   - <TARGET>.lds
#
# the enclave is signed by default ('<TARGET>.signed.so'). The target
# for the unsigned version is '<TARGET>.unsigned'
function(add_sgx_enclave)
    cmake_parse_arguments(ADD_SGX_ENCLAVE "" "TARGET;ENCLAVE_DIR" "LOGIC_CPP_FILES" ${ARGN})
    
    set(PATH_ENCLAVE_PRIVATE_KEY "${ADD_SGX_ENCLAVE_ENCLAVE_DIR}/${ADD_SGX_ENCLAVE_TARGET}_private.pem")
    set(PATH_ENCLAVE_CONFIG_FILE "${ADD_SGX_ENCLAVE_ENCLAVE_DIR}/${ADD_SGX_ENCLAVE_TARGET}.config.xml")
    set(PATH_ENCLAVE_EDL "${ADD_SGX_ENCLAVE_ENCLAVE_DIR}/${ADD_SGX_ENCLAVE_TARGET}.edl")
    set(PATH_ENCLAVE_LDS "${ADD_SGX_ENCLAVE_ENCLAVE_DIR}/${ADD_SGX_ENCLAVE_TARGET}.lds")

    ### TRUSTED BRIDGING (used by this enclave) ###

    # generate the source code for trusted bridging methods (enclave_t.c & enclave_t.h)
    set(PATH_ENCLAVE_T_C "${ADD_SGX_ENCLAVE_TARGET}_t.c")
    set(PATH_ENCLAVE_T_H "${ADD_SGX_ENCLAVE_TARGET}_t.h")
    add_custom_command(
            OUTPUT ${PATH_ENCLAVE_T_C} ${PATH_ENCLAVE_T_H}
            DEPENDS ${SGX_EDGER8R} ${PATH_ENCLAVE_EDL} 
            COMMAND ${SGX_EDGER8R} --trusted ${PATH_ENCLAVE_EDL} 
                --search-path ${ADD_SGX_ENCLAVE_ENCLAVE_DIR} --search-path ${SGX_SDK}/include
    )

    ### ENCLAVE DYNAMIC LIBRARY ###

    # generate the dynamic library (enclave.so)
    add_library(${ADD_SGX_ENCLAVE_TARGET}.unsigned SHARED ${ADD_SGX_ENCLAVE_LOGIC_CPP_FILES} ${PATH_ENCLAVE_T_C})
    set_target_properties(${ADD_SGX_ENCLAVE_TARGET}.unsigned PROPERTIES COMPILE_FLAGS ${ENCLAVE_CPP_FLAGS})
    target_include_directories(${ADD_SGX_ENCLAVE_TARGET}.unsigned PRIVATE ${ENCLAVE_INCLUDE_DIRECTORIES})
    target_link_libraries(${ADD_SGX_ENCLAVE_TARGET}.unsigned ${ENCLAVE_LINK_FLAGS})
    target_compile_definitions(${ADD_SGX_ENCLAVE_TARGET}.unsigned PRIVATE USING_SGX)

    # sign the dynamic library (enclave.signed.so)
    set(ENCLAVE_FILE_NAME "${CMAKE_SHARED_LIBRARY_PREFIX}${ADD_SGX_ENCLAVE_TARGET}.unsigned${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(SIGNED_ENCLAVE_FILE_NAME "${CMAKE_SHARED_LIBRARY_PREFIX}${ADD_SGX_ENCLAVE_TARGET}.signed${CMAKE_SHARED_LIBRARY_SUFFIX}")
    add_custom_command(
            OUTPUT ${SIGNED_ENCLAVE_FILE_NAME}
            DEPENDS ${ADD_SGX_ENCLAVE_TARGET}.unsigned
            COMMAND ${SGX_ENCLAVE_SIGNER} sign -key ${PATH_ENCLAVE_PRIVATE_KEY} -enclave ${ENCLAVE_FILE_NAME}
                -out ${SIGNED_ENCLAVE_FILE_NAME} -config ${PATH_ENCLAVE_CONFIG_FILE}
    )

    # allow developer to select the signed enclave as a build target
    add_custom_target(${ADD_SGX_ENCLAVE_TARGET} ALL DEPENDS ${SIGNED_ENCLAVE_FILE_NAME})

    ### UNTRUSTED BRIDGING (used by applications that interact with this enclave) ###

    # generate the source code for untrusted bridging methods (enclave_u.c & enclave_u.h)
    set(PATH_ENCLAVE_U_C "${ADD_SGX_ENCLAVE_TARGET}_u.c")
    set(PATH_ENCLAVE_U_H "${ADD_SGX_ENCLAVE_TARGET}_u.h")
    add_custom_command(
            OUTPUT ${PATH_ENCLAVE_U_C} ${PATH_ENCLAVE_U_H}
            DEPENDS ${SGX_EDGER8R} ${PATH_ENCLAVE_EDL}
            COMMAND ${SGX_EDGER8R} --untrusted ${PATH_ENCLAVE_EDL} 
                --search-path ${ADD_SGX_ENCLAVE_ENCLAVE_DIR} --search-path ${SGX_SDK}/include
    )

    # add these to the target's properties so that they can be used by the application
    # that interact with this enclave
    set_target_properties(${ADD_SGX_ENCLAVE_TARGET}
            PROPERTIES ENCLAVE_UNTRUSTED_HEADER "${CMAKE_BINARY_DIR}/${PATH_ENCLAVE_U_H}"
                       ENCLAVE_UNTRUSTED_SOURCE "${CMAKE_BINARY_DIR}/${PATH_ENCLAVE_U_C}")
endfunction()
