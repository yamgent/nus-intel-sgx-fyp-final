/**
 * Provides the API interface of the crypto library.
 * 
 * Serves as a bridge between the application and the crypto library.
 * Right now it uses SGX, but it should be replacable by any library
 * that does not use SGX.
 */

#ifndef LIB_CRYPTO_APP_H
#define LIB_CRYPTO_APP_H

#include "sgx_tcrypto.h"
#include <string>

bool lc_init();
bool lc_create_ecc_keypair(sgx_ec256_private_t* private_key, 
    sgx_ec256_public_t* public_key);
bool lc_ecdsa_sign(uint32_t data_size, uint8_t* data, 
    sgx_ec256_private_t private_key, sgx_ec256_signature_t* signature);
bool lc_ecdsa_verify(uint32_t data_size, uint8_t* data,
    sgx_ec256_public_t public_key, sgx_ec256_signature_t* signature, bool* result);
bool lc_ecc_compute_shared_dhkey(sgx_ec256_private_t b, sgx_ec256_public_t ga, 
    sgx_ec256_dh_shared_t* gab);
bool lc_aes_cmac(sgx_cmac_128bit_key_t* key, uint32_t data_size,
    uint8_t* data, sgx_cmac_128bit_tag_t* hash);
bool lc_aes_encrypt(sgx_aes_gcm_128bit_key_t* key,
        uint32_t data_and_output_size, uint8_t* data,
        uint8_t* output,
        uint32_t iv_size, uint8_t* iv,
        sgx_aes_gcm_128bit_tag_t* mac);
bool lc_aes_decrypt(sgx_aes_gcm_128bit_key_t* key,
        uint32_t data_and_output_size, uint8_t* data,
        uint8_t* output,
        uint32_t iv_size, uint8_t* iv,
        sgx_aes_gcm_128bit_tag_t* mac);
bool lc_rand(uint32_t buffer_size, uint8_t* buffer);
bool lc_sha256_hash(uint64_t content_size, 
    const uint8_t* content, sgx_sha256_hash_t* hash);
bool lc_sha256_file_hash(std::string filename, sgx_sha256_hash_t* hash);

#endif
