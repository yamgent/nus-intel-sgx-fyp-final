#ifndef HELPER_APP_NET_EXCHANGE_H
#define HELPER_APP_NET_EXCHANGE_H

#include "sgx_tcrypto.h"
#include "helper_app/helper_app_net_service.h"

bool hane_encrypt_and_send_to_server(hans_NetClient* client,
    uint32_t buffer_size, uint8_t* buffer,
    sgx_cmac_128bit_tag_t* shared_session_key);

bool hane_send_file_to_server(hans_NetClient* client, std::string file_name);
bool hane_receive_file_from_client(hans_NetServer* server, int client_fd, std::string file_name);

#endif
