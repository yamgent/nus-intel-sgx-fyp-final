#ifndef APP_METERWRITER_H
#define APP_METERWRITER_H

#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include <string>
#include "sgx_key_exchange.h"

int service_is_this_my_public_ca_key(sgx_enclave_id_t rewriter_enclave_id, 
    sgx_ec256_public_t public_key, bool* response);
int service_add_meter_and_sign(sgx_enclave_id_t rewriter_enclave_id,
    std::string input_filename, sgx_aes_gcm_128bit_tag_t* input_mac, uint8_t* input_iv,
    std::string output_meter_filename, sgx_aes_gcm_128bit_tag_t* output_mac, uint8_t* output_iv);
int service_attestation_start(sgx_enclave_id_t rewriter_enclave_id,
    sgx_ec256_public_t client_public_key,
    sgx_ra_context_t* ra_context,
    sgx_ra_msg1_t* ra_msg1);
int service_attestation_process_msg2(sgx_enclave_id_t rewriter_enclave_id,
    sgx_ra_context_t ra_context,
    sgx_ra_msg2_t* ra_msg2, sgx_ra_msg3_t** ra_msg3, uint32_t* ra_msg3_actual_size);
int service_attestation_finish(sgx_enclave_id_t rewriter_enclave_id,
    sgx_ra_context_t ra_context);

#endif
