cmake_minimum_required(VERSION 3.9)
project(HelloWorldSgx)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/SgxEnclave.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/SgxApp.cmake)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_SHARED_LIBRARY_PREFIX "")

# metering portion

add_sgx_enclave(
    TARGET enclave_meterwriter
    ENCLAVE_DIR "${CMAKE_CURRENT_LIST_DIR}/enclave_meterwriter/"
    LOGIC_CPP_FILES 
        "enclave_meterwriter/enclave_meterwriter.cpp"
        "helper_enclave/helper_enclave_sha256.cpp"
        "helper_common/helper_common_bufferio.cpp"
        "helper_common/helper_common_meter.cpp"
        "helper_common/helper_common_string.cpp"
        "helper_common/helper_common_array.cpp"
        "helper_enclave/helper_enclave_ca_keypair.cpp"
        "helper_enclave/helper_enclave_attestee.cpp"
        "helper_common/helper_common_meter_logic.cpp"
        "helper_common/helper_common_interface_sha256.cpp"
        )

add_sgx_enclave(
    TARGET lib_crypto
    ENCLAVE_DIR "${CMAKE_CURRENT_LIST_DIR}/lib_crypto/"
    LOGIC_CPP_FILES
        "lib_crypto/lib_crypto.cpp"
        "helper_enclave/helper_enclave_sha256.cpp"
    )

add_sgx_app(
    TARGET app_meterwriter
    LINK_ENCLAVES enclave_meterwriter lib_crypto
    APP_CPP_FILES 
        "app_meterwriter/app_meterwriter.cpp"
        "helper_app/helper_app_attest.cpp"
        "helper_app/helper_app_attest_net.cpp"
        "helper_app/helper_app_sgx.cpp"
        "helper_app/helper_app_fs.cpp"
        "helper_app/helper_app_cert.cpp"
        "helper_app/helper_app_fileio.cpp"
        "app_meterwriter/demo_meterwriter.cpp"
        "helper_app/helper_app_net_service.cpp"
        
        "lib_crypto/lib_crypto_app.cpp"
        "helper_common/helper_common_array.cpp"
    )

add_dependencies(app_meterwriter enclave_meterwriter lib_crypto)

add_sgx_app(
    TARGET app_meterclient
    LINK_ENCLAVES lib_crypto
    APP_CPP_FILES 
        "app_meterclient/app_meterclient.cpp"
        "helper_app/helper_app_net_service.cpp"
        "helper_app/helper_app_attest.cpp"
        "helper_app/helper_app_sgx.cpp"
        "helper_app/helper_app_attest_net.cpp"

        "lib_crypto/lib_crypto_app.cpp"
        "helper_common/helper_common_array.cpp"
        "helper_app/helper_app_fs.cpp"
    )

add_dependencies(app_meterclient lib_crypto)

# nosgx metering
find_package(OpenSSL REQUIRED)

add_executable(nosgx_app_meter 
    nosgx_app_meter/nosgx_app_meter.cpp 
    helper_common/helper_common_bufferio.cpp 
    helper_common/helper_common_meter.cpp 
    helper_common/helper_common_string.cpp
    helper_common/helper_common_meter_logic.cpp
    helper_common/helper_common_interface_sha256.cpp)
target_include_directories(nosgx_app_meter PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(nosgx_app_meter OpenSSL::SSL)
