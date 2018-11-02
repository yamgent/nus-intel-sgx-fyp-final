#include "helper_app_sgx.h"

#include <iostream>
#include <iomanip>

// create an enclave from `enclave_library_path`. `enclave_id` is filled with the id
// of the newly created enclave if creation was successful.
int hasgx_create_enclave(sgx_enclave_id_t* enclave_id, std::string enclave_library_path) {
    sgx_launch_token_t launch_token;
    int launch_token_updated;

    sgx_status_t create_status = sgx_create_enclave(enclave_library_path.c_str(), 1, 
            &launch_token, &launch_token_updated, enclave_id, nullptr);

    if (create_status != SGX_SUCCESS) {
        std::cout << "Enclave creation failed! Ensure that the library '" << enclave_library_path 
            << "' actually exist!" << std::endl;
        return create_status;
    }

    std::cout << "Enclave created using '" << enclave_library_path << "'." << std::endl;
    return 0;
}

// ensures that:
//      - SGX managed to call the enclave's method and returns SGX_SUCCESS
int hasgx_ensure_method_successful(std::string method_name, sgx_status_t method_status) {
    int32_t unused_return_code;
    return hasgx_ensure_method_successful(method_name, method_status, &unused_return_code);
}

// ensures that:
//      - SGX managed to call the enclave's method and returns SGX_SUCCESS
//      - method itself has no problem running and returns SGX_SUCCESS
int hasgx_ensure_method_successful(std::string method_name, sgx_status_t method_status,
        int32_t* method_return_code) {

    if (method_status != SGX_SUCCESS || *method_return_code != SGX_SUCCESS) {
        std::cout << "Call to " << method_name << "() failed! ";

        std::cout << std::hex;
        if (method_status != SGX_SUCCESS) {
            std::cout << "SGX ERROR: 0x" << method_status << std::endl;
        }
        else if (*method_return_code != SGX_SUCCESS) {
            std::cout << "METHOD ERROR: 0x" << *method_return_code << std::endl;
        }
        std::cout << std::dec;
        
        return 1;
    }

    return 0;
}

// print the buffer content
void hasgx_print_buffer(uint32_t size, uint8_t* buffer) {
    std::cout << std::hex;
    std::cout << "(start)" << std::endl;

    for (int i = 0; i < size; i++) {
        std::cout << std::setfill('0') << std::setw(2)
            << (int)buffer[i];
    }
    std::cout << std::endl;

    std::cout << "(end)" << std::endl;
    std::cout << std::dec;
}

// print the contents of the public key to the console
void hasgx_print_public_key_content(sgx_ec256_public_t* public_key) {
    std::cout << std::hex;
    std::cout << "(start)" << std::endl;

    for (int i = 0; i < sizeof(public_key->gx); i++) {
        std::cout << std::setfill('0') << std::setw(2)
            << (int)(public_key->gx[i]);
    }
    std::cout << std::endl;

    for (int i = 0; i < sizeof(public_key->gy); i++) {
        std::cout << std::setfill('0') << std::setw(2)
            << (int)(public_key->gy[i]);
    }
    std::cout << std::endl;

    std::cout << "(end)" << std::endl;
    std::cout << std::dec;
}

// print the contents of the hash to the console
void hasgx_print_hash(sgx_sha256_hash_t* hash) {
    std::cout << std::hex;
    std::cout << "(start)" << std::endl;

    for (int i = 0; i < sizeof(sgx_sha256_hash_t); i++) {
        std::cout << std::setfill('0') << std::setw(2)
            << static_cast<int>((*hash)[i]);
    }
    std::cout << std::endl;

    std::cout << "(end)" << std::endl;
    std::cout << std::dec;
}

// print the contents of the signature to the console
void hasgx_print_signature(sgx_ec256_signature_t* signature) {
    std::cout << std::hex;
    std::cout << "(start)" << std::endl;

    for (int i = 0; i < sizeof(signature->x) / sizeof(uint32_t); i++) {
        std::cout << std::setfill('0') << std::setw(8)
            << (int)(signature->x[i]);
    }
    std::cout << std::endl;

    for (int i = 0; i < sizeof(signature->y) / sizeof(uint32_t); i++) {
        std::cout << std::setfill('0') << std::setw(8)
            << (int)(signature->y[i]);
    }
    std::cout << std::endl;

    std::cout << "(end)" << std::endl;
    std::cout << std::dec;
}

// print the contents of ra_msg1
void hasgx_print_ra_msg1(sgx_ra_msg1_t* ra_msg1) {
    std::cout << "msg1 public key:" << std::endl;
    hasgx_print_public_key_content(&ra_msg1->g_a);
    std::cout << "msg1 gid: " << *((uint32_t*)ra_msg1->gid) << std::endl;
}

void hasgx_print_ra_msg2(sgx_ra_msg2_t* ra_msg2) {
    std::cout << "msg2 g_b: " << std::endl;
    hasgx_print_public_key_content(&ra_msg2->g_b);

    std::cout << "msg2 spid: " << std::endl;
    hasgx_print_buffer(sizeof(ra_msg2->spid), (uint8_t*)&ra_msg2->spid);

    std::cout << "msg2 quote type: " << ra_msg2->quote_type << std::endl;
    std::cout << "msg2 kdf_id: " << ra_msg2->kdf_id << std::endl;

    std::cout << "msg2 sign ga gb: " << std::endl;
    hasgx_print_signature(&ra_msg2->sign_gb_ga);

    std::cout << "msg2 mac: " << std::endl;
    hasgx_print_buffer(sizeof(ra_msg2->mac), (uint8_t*)&ra_msg2->mac);

    std::cout << "msg2 sig_rl_size: " << ra_msg2->sig_rl_size << std::endl;
    if (ra_msg2->sig_rl_size > 0) {
        std::cout << "msg2 sig_rl: " << std::endl;
        hasgx_print_buffer(ra_msg2->sig_rl_size, ra_msg2->sig_rl);
    }
}

void hasgx_print_ra_msg3(uint32_t ra_msg3_size, sgx_ra_msg3_t* ra_msg3) {
    std::cout << "msg3 (total " << ra_msg3_size << " bytes)" << std::endl;
    std::cout << "msg3 mac: " << std::endl;
    hasgx_print_buffer(sizeof(ra_msg3->mac), (uint8_t*)&ra_msg3->mac);

    std::cout << "msg3 g_a: " << std::endl;
    hasgx_print_public_key_content(&ra_msg3->g_a);

    std::cout << "msg3 ps_sec_prop:" << std::endl;
    hasgx_print_buffer(sizeof(ra_msg3->ps_sec_prop), (uint8_t*)&ra_msg3->ps_sec_prop);

    std::cout << "msg3 quote" << std::endl;
    uint32_t quote_size = ra_msg3_size - sizeof(ra_msg3->mac)
        - sizeof(ra_msg3->g_a) - sizeof(ra_msg3->ps_sec_prop);
    hasgx_print_buffer(quote_size, (uint8_t*)ra_msg3->quote);
}
