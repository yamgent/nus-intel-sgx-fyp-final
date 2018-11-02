#include "helper_app_cert.h"
#include "helper_app_sgx.h"
#include <iostream>

void hacert_print_certificate(hacert_metered_code_certificate* certificate) {
    std::cout << " - Hash: " << std::endl;
    hasgx_print_hash(&certificate->hash);

    std::cout << " - Signature: " << std::endl;
    hasgx_print_signature(&certificate->signature);

    std::cout << " - Public key: " << std::endl;
    hasgx_print_public_key_content(&certificate->public_key);
}
