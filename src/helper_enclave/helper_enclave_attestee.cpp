#include "helper_enclave_attestee.h"
#include <cstring>

hea_EnclaveAttestee::hea_EnclaveAttestee() {
    memset(&shared_session_key, 0, sizeof(sgx_cmac_128bit_key_t));
    memset(&ra_context, 0, sizeof(sgx_ra_context_t));
}

int32_t hea_EnclaveAttestee::start_attestation(sgx_ec256_public_t* client_public_key, 
        sgx_ra_context_t* ra_context) {
    int32_t return_code = sgx_ra_init(client_public_key, 0, &this->ra_context);

    if (return_code != SGX_SUCCESS) {
        return return_code;
    }

    memcpy(ra_context, &this->ra_context, sizeof(sgx_ra_context_t));

    return SGX_SUCCESS;
}

int32_t hea_EnclaveAttestee::finish_attestation(sgx_ra_context_t ra_context) {
    if (memcmp(&this->ra_context, &ra_context, sizeof(sgx_ra_context_t))
            != 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return sgx_ra_get_keys(ra_context, SGX_RA_KEY_SK , &shared_session_key);
}
