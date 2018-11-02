#ifndef HELPER_APP_ATTEST_H
#define HELPER_APP_ATTEST_H

#include "sgx_tcrypto.h"
#include "sgx_ukey_exchange.h"

// simulated intel attestation API 
struct intel_attestation_report {
    bool measurement_correct;
};

// simulated intel attestation API
intel_attestation_report send_quote_to_intel(uint32_t data_size, uint8_t* data);

class haa_Attestor {
private:
    sgx_ec256_private_t my_private_key = { 0 };
    sgx_ec256_public_t my_public_key = { 0 };
    sgx_ec256_public_t their_public_key = { 0 };

    sgx_ec256_dh_shared_t shared_ecc_dh_key = { 0 };

    sgx_cmac_128bit_tag_t kdk = { 0 };
    sgx_cmac_128bit_tag_t smk = { 0 };

    bool attest_complete;
    sgx_cmac_128bit_tag_t shared_session_key = { 0 };

public:
    haa_Attestor();

    bool generate_key_pair();

    sgx_ec256_public_t get_my_public_key();

    bool process_msg1(sgx_ra_msg1_t ra_msg1, sgx_ra_msg2_t** ra_msg2, uint32_t* ra_msg2_size);
    bool process_msg3(sgx_ra_msg3_t* ra_msg3, uint32_t ra_msg3_size);

    bool get_shared_session_key(sgx_cmac_128bit_tag_t* session_key);
};

#endif
