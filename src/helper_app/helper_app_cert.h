#ifndef HELPER_APP_CERT_H
#define HELPER_APP_CERT_H

#include "sgx_tcrypto.h"

#define CERTIFICATE_FILENAME_SUFFIX ".certificate"

// a signed certificate representing that the metered version
// of the code is really written by us
struct hacert_metered_code_certificate {
    sgx_sha256_hash_t hash;
    sgx_ec256_signature_t signature;
    sgx_ec256_public_t public_key;
};


void hacert_print_certificate(hacert_metered_code_certificate* certificate);

#endif
