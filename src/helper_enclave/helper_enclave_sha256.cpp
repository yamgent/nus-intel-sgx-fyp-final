#include "helper_enclave_sha256.h"

// given the content, hash it into sha256
int32_t hesha256_hash(uint64_t content_size, const uint8_t* content, sgx_sha256_hash_t* hash) {
    int32_t return_code = SGX_SUCCESS;
    
    sgx_sha_state_handle_t state_handle;
    return_code = sgx_sha256_init(&state_handle);
    if (return_code != SGX_SUCCESS) return return_code;
    return_code = sgx_sha256_update(content, static_cast<uint64_t>(content_size), state_handle);
    if (return_code != SGX_SUCCESS) return return_code;
    return_code = sgx_sha256_get_hash(state_handle, hash);
    if (return_code != SGX_SUCCESS) return return_code;
    return_code = sgx_sha256_close(state_handle);
    if (return_code != SGX_SUCCESS) return return_code;

    return SGX_SUCCESS;
}
