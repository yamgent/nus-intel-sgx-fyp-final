#ifndef HELPER_APP_CA_KEYS_H
#define HELPER_APP_CA_KEYS_H

#include <string>
#include "sgx_urts.h"

struct hack_keypair_management_functions {
    std::string generate_pair_method_name;
    sgx_status_t (*generate_pair_method)(
        sgx_enclave_id_t enclave_id,
        int32_t* return_code,
        uint64_t sealed_buffer_size, 
        uint8_t* sealed_buffer,
        uint64_t* actual_sealed_data_size);

    std::string load_pair_method_name;
    sgx_status_t (*load_pair_method)(
        sgx_enclave_id_t enclave_id,
        int32_t* return_code,
        uint64_t sealed_buffer_size, 
        uint8_t* sealed_buffer);
};

int32_t hack_load_ca_keys(
    sgx_enclave_id_t enclave_id,
    std::string keypair_filename,
    hack_keypair_management_functions methods);

#endif
