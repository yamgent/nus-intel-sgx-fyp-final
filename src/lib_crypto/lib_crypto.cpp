#include "lib_crypto_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "helper_enclave/helper_enclave_sha256.h"

sgx_ecc_state_handle_t g_ecc_state_handle;

// do any cryptography initialization
int32_t lc_ecall_init() {
    return sgx_ecc256_open_context(&g_ecc_state_handle);
}

// generate a private-public keypair
int32_t lc_ecall_create_ecc_keypair(sgx_ec256_private_t* private_key,
        sgx_ec256_public_t* public_key) {    
    return sgx_ecc256_create_key_pair(private_key, public_key, g_ecc_state_handle);
}

// do an ecdsa signature by signing the data using the given private key
int32_t lc_ecall_ecdsa_sign(
            uint32_t data_size, uint8_t* data, 
            sgx_ec256_private_t private_key, 
            sgx_ec256_signature_t* signature) {
    return sgx_ecdsa_sign(data, data_size, &private_key, signature, g_ecc_state_handle);
}

// verify an ecdsa signature by opening the data using the given public key
int32_t lc_ecall_ecdsa_verify(
            uint32_t data_size, uint8_t* data, 
            sgx_ec256_public_t public_key, 
            sgx_ec256_signature_t* signature,
            uint8_t* result) {
    return sgx_ecdsa_verify(data, data_size, &public_key, signature, result, g_ecc_state_handle);
}

// compute the shared DH key gab, given ga and b
int32_t lc_ecall_ecc_compute_shared_dhkey(sgx_ec256_private_t b, sgx_ec256_public_t ga, 
        sgx_ec256_dh_shared_t* gab) {
    // according to intel, sgx_ec256_dh_shared_t entirely stores the x-coordinate of the ECC shared key
    return sgx_ecc256_compute_shared_dhkey(&b, &ga, gab, g_ecc_state_handle);
}

// create an CMAC using an AES key
int32_t lc_ecall_aes_cmac(
        sgx_cmac_128bit_key_t* key,
        uint32_t data_size,
        uint8_t* data,
        sgx_cmac_128bit_tag_t* hash) {
    
    sgx_cmac_state_handle_t cmac_handle;
    int32_t return_code;

    return_code = sgx_cmac128_init(key, &cmac_handle);
    if (return_code != SGX_SUCCESS) {
        return return_code;
    }

    return_code = sgx_cmac128_update(data, data_size, cmac_handle);
    if (return_code != SGX_SUCCESS) {
        return return_code;
    }

    return_code = sgx_cmac128_final(cmac_handle, hash);
    if (return_code != SGX_SUCCESS) {
        return return_code;
    }

    return_code = sgx_cmac128_close(cmac_handle);
    if (return_code != SGX_SUCCESS) {
        return return_code;
    }

    return SGX_SUCCESS;
}

// encrypt using aes key
int32_t lc_ecall_aes_encrypt(sgx_aes_gcm_128bit_key_t* key,
        uint32_t data_and_output_size, uint8_t* data,
        uint8_t* output,
        uint32_t iv_size, uint8_t* iv,
        sgx_aes_gcm_128bit_tag_t* mac) {
    return sgx_rijndael128GCM_encrypt(key, data, data_and_output_size, output, iv, iv_size, nullptr, 0, mac);
}

// decrypt using aes key
int32_t lc_ecall_aes_decrypt(sgx_aes_gcm_128bit_key_t* key,
        uint32_t data_and_output_size, uint8_t* data,
        uint8_t* output,
        uint32_t iv_size, uint8_t* iv,
        sgx_aes_gcm_128bit_tag_t* mac) {
    return sgx_rijndael128GCM_decrypt(key, data, data_and_output_size, output, iv, iv_size, nullptr, 0, mac);
}

// generate random numbers and fill into buffer
int32_t lc_ecall_rand(uint32_t buffer_size, uint8_t* buffer) {
    return sgx_read_rand(buffer, buffer_size);
}

// compute sha256 of a given buffer
int32_t lc_ecall_sha256_hash(uint64_t content_size, const uint8_t* content, sgx_sha256_hash_t* hash) {
    return hesha256_hash(content_size, content, hash);
}
