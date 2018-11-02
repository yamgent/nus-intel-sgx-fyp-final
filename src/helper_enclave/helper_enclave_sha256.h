#ifndef HELPER_ENCLAVE_SHA256_H
#define HELPER_ENCLAVE_SHA256_H

#include "sgx_tcrypto.h"

int32_t hesha256_hash(uint64_t content_size, const uint8_t* content, sgx_sha256_hash_t* hash);

#endif
