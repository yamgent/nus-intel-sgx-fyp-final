#ifndef HELPER_COMMON_INTERFACE_SHA256_H
#define HELPER_COMMON_INTERFACE_SHA256_H

#include "helper_common_values.h"

#ifndef USING_SGX
    #include <openssl/sha.h>

    typedef uint8_t SHA256_HASH[SHA256_DIGEST_LENGTH];
#else
    #include "sgx_tcrypto.h"
    typedef sgx_sha_state_handle_t SHA256_CTX;
    typedef sgx_sha256_hash_t SHA256_HASH;
#endif

int32_t hash_init(SHA256_CTX* sha256_ctx);
int32_t hash_update(SHA256_CTX* sha256_ctx, const uint8_t* buffer, uint64_t buffer_size);
int32_t hash_get(SHA256_CTX* sha256_ctx, SHA256_HASH* hash);
int32_t hash_close(SHA256_CTX* sha256_ctx);

#endif
