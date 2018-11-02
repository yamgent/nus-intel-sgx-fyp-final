#include "helper_app_net_exchange.h"
#include "lib_crypto/lib_crypto_app.h"
#include "helper_common/helper_common_values.h"
#include "helper_common/helper_common_array.h"
#include "helper_app_fs.h"
#include <iostream>

// requires: helper_app_net_service.cpp, helper_app_fs.cpp, helper_common_array.cpp

// encrypt buffer using shared session key, then send it 
// over to the server
bool hane_encrypt_and_send_to_server(
    hans_NetClient* client,
    uint32_t buffer_size, 
    uint8_t* buffer,
    sgx_cmac_128bit_tag_t* shared_session_key) {

    hca_CharArray encrypted(buffer_size);
    uint8_t iv[IV_SIZE] = { 0 };
    sgx_aes_gcm_128bit_tag_t mac = { 0 };

    if (!lc_rand(IV_SIZE, iv)) {
        std::cout << "Fail to generate random IV!" << std::endl;
        return false;
    }

    if (!lc_aes_encrypt((sgx_aes_gcm_128bit_key_t*)shared_session_key, 
            buffer_size, 
            (uint8_t*)&buffer, encrypted.array, IV_SIZE, iv, &mac)) {
        std::cout << "Fail to encrypt buffer!" << std::endl;
        return false;
    }

    if (!client->write(IV_SIZE, iv)) {
        return false;
    }
    if (!client->write(sizeof(sgx_aes_gcm_128bit_tag_t), (uint8_t*)&mac)) {
        return false;
    }
    if (!client->write(encrypted.get_size(), encrypted.array)) {
        return false;
    }

    return true;
}

bool hane_send_file_to_server(hans_NetClient* client, std::string file_name) {
    uint64_t file_size = hafs_get_file_size(file_name);

    if (file_size <= 0) {
        return false;
    }

    hca_CharArray file_content(file_size);
    if (!hafs_read_file_to_buffer(file_name, file_content.get_size(), file_content.array)) {
        return false;
    }

    if (!client->write(sizeof(file_size), (uint8_t*)&file_size)) {
        return false;
    }
    if (!client->write(file_content.get_size(), file_content.array)) {
        return false;
    }

    return true;
}

bool hane_receive_file_from_client(hans_NetServer* server, int client_fd, 
        std::string file_name) {

    uint64_t file_size = 0;
    if (!server->read_fixed(client_fd, sizeof(file_size), (uint8_t*)&file_size)) {
        return false;
    }

    hca_CharArray file_content(file_size);
    if (!server->read_fixed(client_fd, file_content.get_size(), file_content.array)) {
        return false;
    }
    if (!hafs_write_buffer_to_file(file_name, file_content.get_size(), file_content.array)) {
        return false;
    }

    return true;
}
