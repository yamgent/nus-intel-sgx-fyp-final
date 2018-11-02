#ifndef HELPER_ENCLAVE_ATTESTEE_H
#define HELPER_ENCLAVE_ATTESTEE_H

#include "sgx_tcrypto.h"
#include "sgx_tkey_exchange.h"

class hea_EnclaveAttestee {
public:
    sgx_cmac_128bit_key_t shared_session_key;
    sgx_ra_context_t ra_context;

public:
    hea_EnclaveAttestee();
    int32_t start_attestation(sgx_ec256_public_t* client_public_key, 
        sgx_ra_context_t* ra_context);
    int32_t finish_attestation(sgx_ra_context_t ra_context);
};

#endif
