#include "lib_crypto/lib_crypto_app.h"
#include "helper_app/helper_app_net_service.h"
#include "helper_app/helper_app_attest.h"
#include "helper_app/helper_app_sgx.h"
#include "helper_app/helper_app_fs.h"
#include "helper_common/helper_common_array.h"
#include "helper_common/helper_common_values.h"
#include "helper_app/helper_app_cert.h"
#include <iostream>
#include <cstring>
#include "helper_app/helper_app_attest_net.h"

enum meterclient_args_pos {
    ARG_POS_PORT_NUMBER = 1,
    ARG_POS_SERVICE_TYPE,
    ARG_POS_STRING_1,
    ARG_POS_STRING_2
};

struct meterclient_cmd_args {
    int port;
    int service_type;
    char* string1;
    char* string2;
};

int process_args(meterclient_cmd_args* cmd_args, int argc, char** argv) {
    if (argc <= ARG_POS_SERVICE_TYPE) {
        std::cout << "Usage: " << argv[0] << " [port] [service_type]" << std::endl;
        std::cout << std::endl;
        std::cout << "Service 1: Meter writing service" << std::endl;
        std::cout << "Service 2: Public key verification service (include certificate verification)" << std::endl;
        return 1;
    }

    cmd_args->port = std::atoi(argv[ARG_POS_PORT_NUMBER]);
    cmd_args->service_type = std::atoi(argv[ARG_POS_SERVICE_TYPE]);

    switch (cmd_args->service_type) {
        default:
            std::cout << "Invalid service type " << cmd_args->service_type << std::endl;
            return 1;
        case 1:
            if (argc <= ARG_POS_STRING_2) {
                std::cout << "Service 1: Not enough args!" << std::endl;
                std::cout << "Usage: ... [input_name] [output_name]" << std::endl;
                return 1;
            }
            cmd_args->string1 = argv[ARG_POS_STRING_1];
            cmd_args->string2 = argv[ARG_POS_STRING_2];
            break;
        case 2:
            if (argc <= ARG_POS_STRING_1) {
                std::cout << "Service 2: Not enough args!" << std::endl;
                std::cout << "Usage: ... [input_name]" << std::endl;
                return 1;
            }
            cmd_args->string1 = argv[ARG_POS_STRING_1];
            break;
    }
    
    return 0;
}

void print_service_one_meter_status_failed(int meter_status) {
    if (meter_status == HCV_SOURCE_USES_REGISTER_15) {
        std::cout << std::endl;
        std::cout << "Your source code uses %r15 in asm, which is forbidden." << std::endl;
        std::cout << "Please recompile your code with %r15 reserved. In C++," << std::endl;
        std::cout << "that is obtained by adding this as the first line:" << std::endl;
        std::cout << std::endl;
        std::cout << "    register int instruction_counter asm(\"r15\");" << std::endl;
        std::cout << std::endl;
    }
}

int send_request_to_server(hans_NetClient* net_client, meterclient_cmd_args* cmd_args) {
    // start attestation protocol
    sgx_cmac_128bit_tag_t shared_session_key;
    if (haan_do_attestation_client(net_client, &shared_session_key) != 0) {
        return 1;
    }

    std::cout << "Attestation complete! Continue with actual service " << cmd_args->service_type
            << "..." << std::endl;

    // client: send service type
    if (!net_client->write(sizeof(cmd_args->service_type), (uint8_t*)&cmd_args->service_type)) {
        return 1;
    }

    switch (cmd_args->service_type) {
        default:
            std::cout << "No code available to handle service " << cmd_args->service_type << std::endl;
            break;
        case 1:
            {
                std::cout << "Service 1 (meter writing) requested!" << std::endl;

                std::string input_filename(cmd_args->string1);

                hafs_make_dir("temp/");
                hafs_make_dir("temp/app_meterclient/");
                const std::string INPUT_ENCRYPTED_FILENAME = "temp/app_meterclient/input.enc.client";

                sgx_aes_gcm_128bit_tag_t input_mac;
                uint32_t content_size;
                uint8_t input_iv[IV_SIZE];

                if (!lc_rand(IV_SIZE, input_iv)) {
                    std::cout << "Calling lc_rand() failed!" << std::endl;
                    return 1;
                }

                if (!hafs_encrypt_file(input_filename, INPUT_ENCRYPTED_FILENAME,
                        &shared_session_key, &input_mac, input_iv, &content_size)) {
                    return 1;
                }

                hca_CharArray input_encrypted_buffer(content_size);
                if (!hafs_read_file_to_buffer(INPUT_ENCRYPTED_FILENAME, content_size, 
                        input_encrypted_buffer.array)) {
                    return 1;
                }

                // client: send input
                if (!net_client->write(sizeof(input_iv), input_iv)) {
                    return 1;
                }
                if (!net_client->write(sizeof(input_mac), input_mac)) {
                    return 1;
                }
                if (!net_client->write(sizeof(content_size), (uint8_t*)&content_size)) {
                    return 1;
                }
                if (!net_client->write(content_size, input_encrypted_buffer.array)) {
                    return 1;
                }

                std::cout << "Input sent to server!" << std::endl;

                sgx_aes_gcm_128bit_tag_t output_mac;
                uint8_t output_iv[IV_SIZE];
                int meter_status;
                uint32_t output_content_size, output_certificate_size;

                const std::string OUTPUT_ENCRYPTED_FILENAME = "temp/app_meterclient/out.enc.client";

                // server: send output
                if (!net_client->read_fixed(sizeof(meter_status), (uint8_t*)&meter_status)) {
                    return 1;
                }
                if (meter_status != 0) {
                    print_service_one_meter_status_failed(meter_status);
                    return 1;
                } 
                if (!net_client->read_fixed(sizeof(output_iv), output_iv)) {
                    return 1;
                }
                if (!net_client->read_fixed(sizeof(output_mac), output_mac)) {
                    return 1;
                }
                if (!net_client->read_fixed(sizeof(output_content_size), (uint8_t*)&output_content_size)) {
                    return 1;
                }
                hca_CharArray output_encrypted_buffer(output_content_size);
                if (!net_client->read_fixed(output_content_size, output_encrypted_buffer.array)) {
                    return 1;
                }
                if (!net_client->read_fixed(sizeof(output_certificate_size), (uint8_t*)&output_certificate_size)) {
                    return 1;
                }
                hca_CharArray output_certificate_buffer(output_certificate_size);
                if (!net_client->read_fixed(output_certificate_size, output_certificate_buffer.array)) {
                    return 1;
                }


                std::string output_filename(cmd_args->string2);

                if (!hafs_write_buffer_to_file(OUTPUT_ENCRYPTED_FILENAME, output_content_size,
                        output_encrypted_buffer.array)) {
                    return 1;
                }
                if (!hafs_write_buffer_to_file(output_filename + CERTIFICATE_FILENAME_SUFFIX, output_certificate_size,
                        output_certificate_buffer.array)) {
                    return 1;
                }
                if (!hafs_decrypt_file(OUTPUT_ENCRYPTED_FILENAME, output_filename,
                        &shared_session_key, &output_mac, output_iv, &output_content_size)) {
                    return 1;
                }

                std::cout << "Received everything from server!" << std::endl;
            }
            break;
        case 2:
            {
                std::cout << "Service 2 (public key verify) requested!" << std::endl;
                std::cout << "Note: Also include certificate verification" << std::endl;
                
                std::string output_filename(cmd_args->string1);

                hacert_metered_code_certificate certificate;

                // open certificate
                std::ifstream certificate_file(output_filename + CERTIFICATE_FILENAME_SUFFIX, 
                    std::ifstream::binary);
                if (!certificate_file.good()) {
                    std::cout << "Fail to read cetificate file! Ensure that the filename is correct."
                        << std::endl;
                    return 1;
                }
                
                uint64_t ignore_actual_size;
                hafs_read_structure(&certificate_file, 
                    sizeof(certificate), reinterpret_cast<uint8_t*>(&certificate), &ignore_actual_size);

                // client: send public key
                if (!net_client->write(sizeof(certificate.public_key), (uint8_t*)&certificate.public_key)) {
                    return 1;
                }

                bool certificate_response_code;

                // server: send response
                if (!net_client->read_fixed(sizeof(certificate_response_code), 
                        (uint8_t*)&certificate_response_code)) {
                    return 1;
                }

                // verifiy public key in certificate
                if (!certificate_response_code) {
                    std::cout << "Public key is NOT from the enclave! :(" << std::endl;
                    return 1;
                } else {
                    std::cout << "Public key verified from enclave!" << std::endl;
                }
                
                // verify hash in certificate
                sgx_sha256_hash_t computed_hash;
                if (!lc_sha256_file_hash(output_filename, &computed_hash)) {
                    std::cout << "Fail to compute hash of " << output_filename << "!" << std::endl;
                    return 1;
                }
                if (memcmp(certificate.hash, computed_hash, sizeof(sgx_sha256_hash_t)) != 0) {
                    std::cout << "Computed hash mismatch certificate hash!" << std::endl;
                    std::cout << " - Computed Hash: " << std::endl;
                    hasgx_print_hash(&computed_hash);
                    std::cout << " - Certificate Hash: " << std::endl;
                    hasgx_print_hash(&certificate.hash);

                    return 1;
                } else {
                    std::cout << "Hash matched!" << std::endl;
                    std::cout << " - Hash: " << std::endl;
                    hasgx_print_hash(&computed_hash);
                }

                // verify signature in certificate
                bool signature_verification_result;
                if (!lc_ecdsa_verify(sizeof(sgx_sha256_hash_t), certificate.hash, certificate.public_key,
                        &certificate.signature, &signature_verification_result)) {
                    std::cout << "Call to lc_ecdsa_verify() failed!" << std::endl;
                    return 1;
                }

                if (!signature_verification_result) {
                    std::cout << "Signature verification failed!" << std::endl;
                    return 1;
                } else {
                    std::cout << "Signature valid!" << std::endl;
                }

                std::cout << "Certificate and metered file verified, and are AUTHENTIC." << std::endl;
            }
            break;
    }

    return 0;
}

int main(int argc, char** argv) {
    meterclient_cmd_args cmd_args = { 0 };
    if (process_args(&cmd_args, argc, argv) != 0) {
        return 1;
    }

    if (!lc_init()) {
        std::cout << "Fail to initialize lib_crypto!" << std::endl;
        return 1;
    }

    hans_NetClient net_client;
    if (!net_client.init_with_port("127.0.0.1", cmd_args.port)) return 1;
    if (!net_client.connect()) return 1;

    std::cout << "Connected to " << cmd_args.port << "!" << std::endl;

    send_request_to_server(&net_client, &cmd_args);

    net_client.close();

    std::cout << "Closed connection to " << cmd_args.port << "!" << std::endl;

    return 0;
}
