#include "helper_enclave_ca_keypair.h"
#include "sgx_tseal.h"
#include <cstring>

heck_Keypair::heck_Keypair() {
    memset(&this->private_key, 0, sizeof(sgx_ec256_private_t));
    memset(&this->public_key, 0, sizeof(sgx_ec256_public_t));
}

// generate a new CA key pair, returns the sealed data
int32_t heck_Keypair::generate_new_keypair(sgx_ecc_state_handle_t* ecc_state_handle,
        uint64_t sealed_buffer_size, 
        uint8_t* sealed_buffer,
        uint64_t* actual_sealed_data_size) {
    uint32_t return_code = SGX_SUCCESS;

    return_code = sgx_ecc256_create_key_pair(&private_key, &public_key, *ecc_state_handle);
    if (return_code != SGX_SUCCESS) {
        return return_code;
    }

    *actual_sealed_data_size = sgx_calc_sealed_data_size(0, sizeof(*this));
    if (sealed_buffer_size < *actual_sealed_data_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_sealed_data_t* sealed_data = reinterpret_cast<sgx_sealed_data_t*>(sealed_buffer);
    return_code = sgx_seal_data(0, nullptr,
        sizeof(*this), reinterpret_cast<uint8_t*>(this),
        *actual_sealed_data_size, sealed_data);
    if (return_code != SGX_SUCCESS) {
        return return_code;
    }

    return SGX_SUCCESS;
}

// load an existing CA key pair from the sealed data
int32_t heck_Keypair::load_keypair(
        uint64_t sealed_buffer_size, 
        uint8_t* sealed_buffer) {
    uint32_t return_code = SGX_SUCCESS;

    sgx_sealed_data_t* sealed_data = reinterpret_cast<sgx_sealed_data_t*>(sealed_buffer);
    uint32_t sealed_data_length;

    return_code = sgx_unseal_data(sealed_data, 
        nullptr, nullptr, 
        reinterpret_cast<uint8_t*>(this), &sealed_data_length);
    if (return_code != SGX_SUCCESS) {
        return return_code;
    }
    if (sealed_data_length != sizeof(*this)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return SGX_SUCCESS;
}

// returns the public CA key
int32_t heck_Keypair::get_public_key(sgx_ec256_public_t* copy_public_key) {
    for (int i = 0; i < sizeof(copy_public_key->gx); i++) {
        copy_public_key->gx[i] = public_key.gx[i];
    }
    for (int i = 0; i < sizeof(copy_public_key->gy); i++) {
        copy_public_key->gy[i] = public_key.gy[i];
    }

    return SGX_SUCCESS;
}

// is this public CA the same as my public key?
//
// `result_equal` will be:
//      - 1 if yes, this is my key
//      - 0 if no, this is NOT my key
int32_t heck_Keypair::is_public_key_equal(sgx_ec256_public_t* other_public_key, 
        int8_t* result_equal) {
    *result_equal = 0;

    uint8_t* theirs_char = reinterpret_cast<uint8_t*>(other_public_key);
    uint8_t* my_char = reinterpret_cast<uint8_t*>(&public_key);

    bool matched = true;
    for (int i = 0; i < sizeof(sgx_ec256_public_t); i++) {
        if (theirs_char[i] != my_char[i]) {
            matched = false;
            break;  // we don't have to worry about timing attack; public key is supposed
                    // to be public anyway!
        }
    }

    if (matched) {
        *result_equal = 1;
    }

    return SGX_SUCCESS;      
}
