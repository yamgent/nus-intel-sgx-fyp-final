#include "enclave_meterwriter_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include <cstring>

#include "helper_enclave/helper_enclave_sha256.h"
#include "helper_common/helper_common_bufferio.h"
#include "helper_common/helper_common_array.h"
#include "helper_common/helper_common_values.h"
#include "helper_enclave/helper_enclave_ca_keypair.h"
#include "helper_enclave/helper_enclave_attestee.h"
#include "helper_common/helper_common_meter_logic.h"

#include <queue>
#include <string>

#include "sgx_key_exchange.h"
#include "sgx_tkey_exchange.h"

sgx_ecc_state_handle_t g_ecc_state_handle;
heck_Keypair g_keypair;
hea_EnclaveAttestee g_enclave_attestee;

#define IV_SIZE 12

// initialize cryptography functions
int32_t ecall_initialize() {
    return sgx_ecc256_open_context(&g_ecc_state_handle);
}

// generate a new CA key pair, returns the sealed data
int32_t ecall_generate_ca_key_pair(uint64_t sealed_buffer_size, uint8_t* sealed_buffer,
        uint64_t* actual_sealed_data_size) {
    return g_keypair.generate_new_keypair(&g_ecc_state_handle,
        sealed_buffer_size, sealed_buffer, actual_sealed_data_size);
}

// load an existing CA key pair from the sealed data
int32_t ecall_load_ca_key_pair(uint64_t sealed_buffer_size, uint8_t* sealed_buffer) {
    return g_keypair.load_keypair(sealed_buffer_size, sealed_buffer);
}

// is this public CA mine and not compromised?
//
// `result_is_my_key` will be:
//      - 1 if yes, this is my key
//      - 0 if no, this is NOT my key
int32_t ecall_is_my_public_ca_key(sgx_ec256_public_t* public_key, int8_t* result_is_my_key) {
    return g_keypair.is_public_key_equal(public_key, result_is_my_key);
}

// returns the public CA key
int32_t ecall_get_public_ca_key(sgx_ec256_public_t* public_key) {
    return g_keypair.get_public_key(public_key);
}

int32_t ecall_start_attestation(
        sgx_ec256_public_t* client_public_key, sgx_ra_context_t* ra_context) {
    return g_enclave_attestee.start_attestation(client_public_key, ra_context);
}

int32_t ecall_finish_attestation(sgx_ra_context_t ra_context) {
    return g_enclave_attestee.finish_attestation(ra_context);
}

// write line to a buffer and do SHA-256 hashing
int32_t write_line_to_buffer_and_sha256hash(
        hcbio_StringWriter* writer,
        std::string output_line,
        sgx_sha_state_handle_t sha_state_handle) {

    int32_t return_code = SGX_SUCCESS;

    // write
    writer->write_line(output_line);

    // hash
    return_code = sgx_sha256_update(reinterpret_cast<const uint8_t*>(output_line.c_str()),
        output_line.size(), sha_state_handle);
    if (return_code != SGX_SUCCESS) return return_code;

    return_code = sgx_sha256_update(reinterpret_cast<const uint8_t*>("\n"),
        1, sha_state_handle);
    if (return_code != SGX_SUCCESS) return return_code;

    return SGX_SUCCESS;
}

// add metering to the code and sign it
int32_t ecall_add_meter_and_sign(
        uint32_t input_buffer_size, uint8_t* input_buffer,
        uint32_t actual_input_size, sgx_aes_gcm_128bit_tag_t* input_mac,
        uint8_t* input_iv,
        uint32_t output_buffer_size, uint8_t* output_buffer, 
        uint32_t* actual_output_size, sgx_aes_gcm_128bit_tag_t* output_mac,
        uint8_t* output_iv,
        sgx_sha256_hash_t* hash, sgx_ec256_signature_t* signature) {

    uint32_t return_code = SGX_SUCCESS;

    sgx_aes_gcm_128bit_key_t* key = &g_enclave_attestee.shared_session_key;

    hca_CharArray decrypted_input_buffer(actual_input_size);
    hca_CharArray decrypted_output_buffer(output_buffer_size);

    // decrypt
    return_code = sgx_rijndael128GCM_decrypt(key, 
        input_buffer, actual_input_size, 
        decrypted_input_buffer.array, input_iv, IV_SIZE, nullptr, 0, input_mac);
    if (return_code != SGX_SUCCESS) return return_code;

    // add meter
    uint64_t acutal_output_size64;
    return_code = hcml_add_meter_and_generate_hash(
        input_buffer_size, decrypted_input_buffer.array, actual_input_size,
        output_buffer_size, decrypted_output_buffer.array, &acutal_output_size64,
        hash);
    if (return_code != SGX_SUCCESS) return return_code;
    *actual_output_size = (uint32_t)acutal_output_size64;

    // generate output IV
    return_code = sgx_read_rand(output_iv, IV_SIZE);
    if (return_code != SGX_SUCCESS) return return_code;

    // encrypt
    return_code = sgx_rijndael128GCM_encrypt(key,
        decrypted_output_buffer.array, *actual_output_size,
        output_buffer, output_iv, IV_SIZE, nullptr, 0, output_mac);

    // sign the hash
    return_code = sgx_ecdsa_sign(
        reinterpret_cast<const uint8_t*>(hash),
        sizeof(sgx_sha256_hash_t),
        &g_keypair.private_key,
        signature,
        g_ecc_state_handle);
    if (return_code != SGX_SUCCESS) return return_code;

    return SGX_SUCCESS;
}
