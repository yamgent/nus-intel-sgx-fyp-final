/**
 * Provides the API interface of the crypto library.
 * 
 * Serves as a bridge between the application and the crypto library.
 * Right now it uses SGX, but it should be replacable by any library
 * that does not use SGX.
 */

#include "lib_crypto_app.h"
#include "lib_crypto_u.h"

#include "sgx_urts.h"

#include <iostream>
#include "helper_app/helper_app_fs.h"
#include "helper_common/helper_common_array.h"

sgx_enclave_id_t g_lc_enclave_id;

// initialize the crypto library
bool lc_init() {
    sgx_launch_token_t launch_token;
    int launch_token_updated;

    if (sgx_create_enclave("lib_crypto.signed.so", 1, 
        &launch_token, &launch_token_updated, 
        &g_lc_enclave_id, nullptr) != SGX_SUCCESS) {
        return false;
    }

    int32_t return_code;
    if (lc_ecall_init(g_lc_enclave_id, &return_code) != SGX_SUCCESS
            || return_code != SGX_SUCCESS) {
        return false;
    }
    
    return true;
}

// generate a private-public ecc keypair
bool lc_create_ecc_keypair(sgx_ec256_private_t* private_key, 
        sgx_ec256_public_t* public_key) {

    int32_t return_code;
    if (lc_ecall_create_ecc_keypair(g_lc_enclave_id, &return_code, 
            private_key, public_key) != SGX_SUCCESS
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true;
}

// sign a data using an ec256 private key
bool lc_ecdsa_sign(uint32_t data_size, uint8_t* data, 
        sgx_ec256_private_t private_key, sgx_ec256_signature_t* signature) {
    int32_t return_code;
    if (lc_ecall_ecdsa_sign(g_lc_enclave_id, &return_code, 
            data_size, data, private_key, signature) != SGX_SUCCESS
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true;        
}

// verify a data using an ec256 public key
bool lc_ecdsa_verify(uint32_t data_size, uint8_t* data,
    sgx_ec256_public_t public_key, sgx_ec256_signature_t* signature, bool* result) {

    uint8_t result_int = 0;
    int32_t return_code = 0;
    if (lc_ecall_ecdsa_verify(g_lc_enclave_id, &return_code, 
            data_size, data, public_key, signature, &result_int) != SGX_SUCCESS
            || return_code != SGX_SUCCESS) {
        return false;
    }

    switch(result_int) {
        default:
            std::cout << "lc_ecall_ecdsa_verify() returned strange result." << std::endl;
            *result = false;
            break;
        case SGX_EC_VALID:
            *result = true;
            break;
        case SGX_EC_INVALID_SIGNATURE:
            *result = false;
            break;
    }

    return true; 
}

// compute a shared ecc DH key gab, given b and ga
bool lc_ecc_compute_shared_dhkey(sgx_ec256_private_t b, sgx_ec256_public_t ga, 
        sgx_ec256_dh_shared_t* gab) {
    
    int32_t return_code;
    if (lc_ecall_ecc_compute_shared_dhkey(g_lc_enclave_id, &return_code, 
            b, ga, gab) != SGX_SUCCESS 
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true;        
}

// create a CMAC using an AES key
bool lc_aes_cmac(sgx_cmac_128bit_key_t* key, uint32_t data_size,
        uint8_t* data, sgx_cmac_128bit_tag_t* hash) {

    int32_t return_code;
    if (lc_ecall_aes_cmac(g_lc_enclave_id, &return_code, 
            key, data_size, data, hash) != SGX_SUCCESS 
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true;  
}

// encrypt data using an AES key
bool lc_aes_encrypt(sgx_aes_gcm_128bit_key_t* key,
        uint32_t data_and_output_size, uint8_t* data,
        uint8_t* output,
        uint32_t iv_size, uint8_t* iv,
        sgx_aes_gcm_128bit_tag_t* mac) {

    if (iv_size != 12) {
        std::cout << "lc_aes_encrypt(): IV size must be 12!" << std::endl;
        return false;
    }

    int32_t return_code;
    if (lc_ecall_aes_encrypt(g_lc_enclave_id, &return_code, 
            key, data_and_output_size, data, output, iv_size, iv, mac) != SGX_SUCCESS 
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true;
}

// decrypt data using an AES key
bool lc_aes_decrypt(sgx_aes_gcm_128bit_key_t* key,
        uint32_t data_and_output_size, uint8_t* data,
        uint8_t* output,
        uint32_t iv_size, uint8_t* iv,
        sgx_aes_gcm_128bit_tag_t* mac) {
    
    if (iv_size != 12) {
        std::cout << "lc_aes_decrypt(): IV size must be 12!" << std::endl;
        return false;
    }

    int32_t return_code;
    if (lc_ecall_aes_decrypt(g_lc_enclave_id, &return_code, 
            key, data_and_output_size, data, output, iv_size, iv, mac) != SGX_SUCCESS 
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true;
}

// generate random numbers and fill it in the buffer
bool lc_rand(uint32_t buffer_size, uint8_t* buffer) {

    int32_t return_code;
    if (lc_ecall_rand(g_lc_enclave_id, &return_code, 
            buffer_size, buffer) != SGX_SUCCESS 
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true; 
}

// get the sha256 hash of a given buffer
bool lc_sha256_hash(uint64_t content_size, 
    const uint8_t* content, sgx_sha256_hash_t* hash) {

    int32_t return_code;
    if (lc_ecall_sha256_hash(g_lc_enclave_id, &return_code, 
            content_size, content, hash) != SGX_SUCCESS 
            || return_code != SGX_SUCCESS) {
        return false;
    }

    return true; 
}

bool lc_sha256_file_hash(std::string filename, sgx_sha256_hash_t* hash) {
    if (!hafs_file_exist(filename)) {
        return false;
    }

    uint32_t file_size = hafs_get_file_size(filename);
    hca_CharArray file_array(file_size);
    std::ifstream file_stream(filename);
    file_stream.read(reinterpret_cast<char *>(file_array.array), file_size);
    file_stream.close();

    return lc_sha256_hash(file_size, file_array.array, hash);
}
