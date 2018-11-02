#include "helper_common_interface_sha256.h"

#ifndef USING_SGX
    #include <openssl/sha.h>
    #include <iostream>

    typedef uint8_t SHA256_HASH[SHA256_DIGEST_LENGTH];

    int32_t hash_init(SHA256_CTX* sha256_ctx) {
        if (SHA256_Init(sha256_ctx) != 1) {
            std::cout << "SHA256_Init failed" << std::endl;
            return RET_ERROR;
        }
        return RET_SUCCESS;
    }

    int32_t hash_update(SHA256_CTX* sha256_ctx, const uint8_t* buffer, uint64_t buffer_size) {
        if (SHA256_Update(sha256_ctx, buffer, buffer_size) != 1) {
            std::cout << "SHA256_Update failed" << std::endl;
            return RET_ERROR;
        }
        return RET_SUCCESS;
    }

    int32_t hash_get(SHA256_CTX* sha256_ctx, SHA256_HASH* hash) {
        if (SHA256_Final(*hash, sha256_ctx) != 1) {
            std::cout << "SHA256_FINAL failed" << std::endl;
            return RET_ERROR;
        }
        return RET_SUCCESS;
    }

    int32_t hash_close(SHA256_CTX* sha256_ctx) {
        // do nothing for openssl
        return RET_SUCCESS;
    }
#else
    #include "sgx_tcrypto.h"
    int32_t hash_init(SHA256_CTX* sha256_ctx) {
        return sgx_sha256_init(sha256_ctx);
    }

    int32_t hash_update(SHA256_CTX* sha256_ctx, const uint8_t* buffer, uint64_t buffer_size) {
        return sgx_sha256_update(buffer, buffer_size, *sha256_ctx);
    }

    int32_t hash_get(SHA256_CTX* sha256_ctx, SHA256_HASH* hash) {
        return sgx_sha256_get_hash(*sha256_ctx, hash);
    }

    int32_t hash_close(SHA256_CTX* sha256_ctx) {
        return sgx_sha256_close(*sha256_ctx);
    }
#endif