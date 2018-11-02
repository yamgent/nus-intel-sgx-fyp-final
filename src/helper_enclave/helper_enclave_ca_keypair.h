#ifndef HELPER_ENCLAVE_CA_KEYPAIR_H
#define HELPER_ENCLAVE_CA_KEYPAIR_H

#include "sgx_tcrypto.h"

class heck_Keypair {
public:
    sgx_ec256_private_t private_key;
    sgx_ec256_public_t public_key;

public:
    heck_Keypair();
    int32_t generate_new_keypair(sgx_ecc_state_handle_t* ecc_state_handle,
        uint64_t sealed_buffer_size,
        uint8_t* sealed_buffer,
        uint64_t* actual_sealed_data_size);
    int32_t load_keypair(uint64_t sealed_buffer_size, uint8_t* sealed_buffer);
    int32_t get_public_key(sgx_ec256_public_t* copy_public_key);
    int32_t is_public_key_equal(sgx_ec256_public_t* other_public_key, int8_t* result_equal);
};

#endif
