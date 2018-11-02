#include "helper_app_attest_net.h"

#include "helper_app_net_service.h"
#include "helper_app_attest.h"
#include <iostream>

// users of this file must include "helper_app_attest.cpp" (pure attest version)

int haan_do_attestation_client(hans_NetClient* net_client, sgx_cmac_128bit_tag_t* shared_session_key) {
    sgx_ra_context_t ra_context;
    haa_Attestor attestor;
    if (!attestor.generate_key_pair()) {
        return 1;
    }

    sgx_ec256_public_t my_public_key = attestor.get_my_public_key();

    //std::cout << "My public key" << std::endl;
    //hasgx_print_public_key_content(&my_public_key);

    // client: send public key
    if (!net_client->write(sizeof(sgx_ec256_public_t), (uint8_t*)&my_public_key)) {
        return 1;
    }

    // server: send msg1
    sgx_ra_msg1_t ra_msg1;
    if (!net_client->read_fixed(sizeof(sgx_ra_msg1_t), (uint8_t*)&ra_msg1)) {
        return 1;
    }

    //hasgx_print_ra_msg1(&ra_msg1);

    // client: send msg2
    sgx_ra_msg2_t* ra_msg2;
    uint32_t ra_msg2_actual_size;
    if (!attestor.process_msg1(ra_msg1, &ra_msg2, &ra_msg2_actual_size)) {
        return 1;
    }

    //hasgx_print_ra_msg2(ra_msg2);

    if (!net_client->write(sizeof(sgx_ra_msg2_t), (uint8_t*)ra_msg2)) {
        return 1;
    }

    // server: send msg3
    sgx_ra_msg3_t* ra_msg3;
    uint32_t ra_msg3_size;
    if (!net_client->read(&ra_msg3_size, (uint8_t**)&ra_msg3)) {
        return 1;
    }

    //hasgx_print_ra_msg3(ra_msg3_size, ra_msg3);

    // client: send attestation successful
    if (!attestor.process_msg3(ra_msg3, ra_msg3_size)) {
        return 1;
    }
    free(ra_msg3);

    if (!attestor.get_shared_session_key(shared_session_key)) {
        return 1;
    }

    bool successful = true;
    if (!net_client->write(sizeof(bool), (uint8_t*)&successful)) {
        return 1;
    }

    return 0;
}

int haan_do_attestation_server(sgx_enclave_id_t enclave_id, hans_NetServer* net_server, int client_fd,
        server_attestation_function_pointers attestation_functions) {
    uint32_t message_size;

    // client: send public key
    sgx_ec256_public_t client_public_key;
    if (!net_server->read_fixed(client_fd, sizeof(sgx_ec256_public_t), (uint8_t*)&client_public_key)) {
        return 1;
    }

    //std::cout << "Client public key:" << std::endl;
    //hasgx_print_public_key_content(&client_public_key);

    // server: send msg1
    sgx_ra_context_t ra_context;
    sgx_ra_msg1_t ra_msg1;
    if (attestation_functions.start_attestation(enclave_id, 
            client_public_key, &ra_context, &ra_msg1) != 0) {
        return 1;
    }

    //hasgx_print_ra_msg1(&ra_msg1);

    if (!net_server->write(client_fd, sizeof(ra_msg1), (uint8_t*)&ra_msg1)) {
        return 1;
    }

    // client: send msg2
    sgx_ra_msg2_t ra_msg2;
    if (!net_server->read_fixed(client_fd, sizeof(sgx_ra_msg2_t), (uint8_t*)&ra_msg2)) {
        return 1;
    }

    //hasgx_print_ra_msg2(&ra_msg2);

    // server: send msg3
    sgx_ra_msg3_t* ra_msg3;
    uint32_t ra_msg3_actual_size;
    if (attestation_functions.proc_msg2(enclave_id, ra_context,
            &ra_msg2, &ra_msg3, &ra_msg3_actual_size) != 0) {
        return 1;
    }

    //hasgx_print_ra_msg3(ra_msg3_actual_size, ra_msg3);

    if (!net_server->write(client_fd, ra_msg3_actual_size, (uint8_t*)ra_msg3)) {
        free(ra_msg3);
        return 1;
    }

    free(ra_msg3);

    // client: send attestation successful
    bool successful;
    if (!net_server->read_fixed(client_fd, sizeof(bool), (uint8_t*)&successful)) {
        return 1;
    }

    if (!successful) {
        std::cout << "Something wrong with attestation on client side." << std::endl;
        return 1;
    }

    if (attestation_functions.finish_attestation(enclave_id, ra_context) != 0) {
        return 1;
    }

    return 0;
}
