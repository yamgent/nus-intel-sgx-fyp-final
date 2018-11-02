#ifndef HELPER_APP_ATTEST_NET_H
#define HELPER_APP_ATTEST_NET_H

#include "sgx_key_exchange.h"
#include "helper_app_net_service.h"
#include "sgx_urts.h"

struct server_attestation_function_pointers {
    int (*start_attestation)(
        sgx_enclave_id_t enclave_id,
        sgx_ec256_public_t client_public_key,
        sgx_ra_context_t* ra_context,
        sgx_ra_msg1_t* ra_msg1);

    int (*proc_msg2)(
        sgx_enclave_id_t enclave_id,
        sgx_ra_context_t ra_context,
        sgx_ra_msg2_t* ra_msg2, 
        sgx_ra_msg3_t** ra_msg3, 
        uint32_t* ra_msg3_actual_size);

    int (*finish_attestation)(
        sgx_enclave_id_t enclave_id,
        sgx_ra_context_t ra_context);
};

int haan_do_attestation_client(hans_NetClient* net_client, sgx_cmac_128bit_tag_t* shared_session_key);
int haan_do_attestation_server(sgx_enclave_id_t rewriter_enclave_id, hans_NetServer* net_server, int client_fd,
    server_attestation_function_pointers attestation_functions);

#endif
