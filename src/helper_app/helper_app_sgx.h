#ifndef HELPER_APP_SGX_H
#define HELPER_APP_SGX_H

#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include <string>
#include "sgx_key_exchange.h"

int hasgx_create_enclave(sgx_enclave_id_t* enclave_id, std::string enclave_library_path);

int hasgx_ensure_method_successful(std::string method_name, sgx_status_t method_status);
int hasgx_ensure_method_successful(std::string method_name, sgx_status_t method_status,
    int32_t* method_return_code);

void hasgx_print_buffer(uint32_t size, uint8_t* buffer);

void hasgx_print_public_key_content(sgx_ec256_public_t* public_key);
void hasgx_print_hash(sgx_sha256_hash_t* hash);
void hasgx_print_signature(sgx_ec256_signature_t* signature);

void hasgx_print_ra_msg1(sgx_ra_msg1_t* ra_msg1);
void hasgx_print_ra_msg2(sgx_ra_msg2_t* ra_msg2);
void hasgx_print_ra_msg3(uint32_t ra_msg3_size, sgx_ra_msg3_t* ra_msg3);

#endif
