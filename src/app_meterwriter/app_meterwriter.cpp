#include "enclave_meterwriter_u.h"

#define KEYPAIR_FILE "keypair.sealed.bin"

#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>

#include "helper_app/helper_app_sgx.h"
#include "helper_app/helper_app_fs.h"
#include "helper_app/helper_app_cert.h"
#include "demo_meterwriter.h"
#include "sgx_ukey_exchange.h"
#include "helper_common/helper_common_values.h"
#include "helper_app/helper_app_net_service.h"
#include "helper_common/helper_common_array.h"
#include "helper_app/helper_app_attest_net.h"

int initialize_rewriter_enclave(sgx_enclave_id_t rewriter_enclave_id) {
    int32_t ecall_return_code = 0;

    // ### let the enclave initialize itself ###
    if (hasgx_ensure_method_successful(
            "ecall_initialize",
            ecall_initialize(rewriter_enclave_id, &ecall_return_code),
            &ecall_return_code)
            != 0) {
        return 1;
    }

    std::cout << "Enclave basic initialization complete." << std::endl;

    // ### generate keypair if we don't have an existing one ###
    if (!hafs_file_exist(KEYPAIR_FILE)) {
        uint8_t sealed_data_buffer[1000];
        uint64_t actual_sealed_size;

        if (hasgx_ensure_method_successful(
                "ecall_generate_ca_key_pair",
                ecall_generate_ca_key_pair(rewriter_enclave_id, &ecall_return_code,
                    sizeof(sealed_data_buffer), sealed_data_buffer,
                    &actual_sealed_size),
                &ecall_return_code)
                != 0) {
            return 1;
        }

        std::ofstream output_keypair_file(KEYPAIR_FILE, std::fstream::binary);
        hafs_write_structure(&output_keypair_file, actual_sealed_size, sealed_data_buffer);
        output_keypair_file.close();

        std::cout << "No " << KEYPAIR_FILE << " found so generating new keypair..." << std::endl;
    }

    // ### load CA keypair ###
    {
        std::ifstream keypair_file(KEYPAIR_FILE, std::fstream::binary);
        uint8_t sealed_data_buffer[1000];
        uint64_t actual_sealed_size;

        hafs_read_structure(&keypair_file, sizeof(sealed_data_buffer), sealed_data_buffer, &actual_sealed_size);
        if (actual_sealed_size > sizeof(sealed_data_buffer)) {
            std::cout << "Programmer Error: sealed_data_buffer not big enough." << std::endl;
            return 1;
        }

        if (hasgx_ensure_method_successful(
                "ecall_load_ca_key_pair",
                ecall_load_ca_key_pair(rewriter_enclave_id, &ecall_return_code,
                    sizeof(sealed_data_buffer), sealed_data_buffer),
                &ecall_return_code)
                != 0) {
            return 1;
        }

        std::cout << "CA keypair '" << KEYPAIR_FILE << "' loaded!" << std::endl;
    }

    return 0;
}

int service_is_this_my_public_ca_key(sgx_enclave_id_t rewriter_enclave_id, 
        sgx_ec256_public_t public_key, bool* response) {
    // ### console output: display input ###
    std::cout << "========================" << std::endl;
    std::cout << "> Service Request: Is this my public CA key?" << std::endl;
    std::cout << ">     Content of public key queried:" << std::endl;
    hasgx_print_public_key_content(&public_key);
    std::cout << "> " << std::endl;
    
    // ### run actual service ###
    int32_t ecall_return_code = 0;
    int8_t result_is_my_key = 0;

    if (hasgx_ensure_method_successful(
            "ecall_is_my_public_ca_key",
            ecall_is_my_public_ca_key(rewriter_enclave_id, &ecall_return_code,
                &public_key, &result_is_my_key),
            &ecall_return_code)
            != 0) {
        std::cout << "========================" << std::endl;
        return 1;
    }

    *response = (result_is_my_key != 0);

    // ### console output: display result ###
    std::cout << "> Service Response: ";
    if (*response) {
        std::cout << "YES" << std::endl;
    } else { 
        std::cout << "NO" << std::endl;
    }
    std::cout << "========================" << std::endl;
    
    return 0;
}

int service_add_meter_and_sign(sgx_enclave_id_t rewriter_enclave_id,
        std::string input_filename, sgx_aes_gcm_128bit_tag_t* input_mac, uint8_t* input_iv,
        std::string output_meter_filename, sgx_aes_gcm_128bit_tag_t* output_mac, uint8_t* output_iv) {
    
    // ### console output: display input ###
    std::cout << "========================" << std::endl;
    std::cout << "> Service Request: Add meter and sign" << std::endl;
    std::cout << "> " << std::endl;
    
    // ### run actual service ###
    int32_t ecall_return_code = 0;
    hacert_metered_code_certificate certificate;

    // read the meter file into an input buffer and create an output buffer
    uint8_t input_buffer[MAX_INPUT_OUTPUT_FILE_SIZE], output_buffer[MAX_INPUT_OUTPUT_FILE_SIZE];
    uint32_t actual_input_size, actual_output_size;

    std::ifstream input_file_stream(input_filename);

    if (!input_file_stream.good()) {
        std::cout << "Cannot open file " << input_filename << "!" << std::endl;
        return SGX_ERROR_INVALID_PARAMETER;
    }
    input_file_stream.read(reinterpret_cast<char*>(input_buffer), MAX_INPUT_OUTPUT_FILE_SIZE);
    actual_input_size = input_file_stream.gcount();
    input_file_stream.close();

    std::cout << "Read " << input_filename << " that has " << actual_input_size << " bytes." << std::endl;

    // do metering and signing
    if (hasgx_ensure_method_successful(
            "ecall_add_meter_and_sign",
            ecall_add_meter_and_sign(rewriter_enclave_id, &ecall_return_code,
                MAX_INPUT_OUTPUT_FILE_SIZE,
                input_buffer,
                actual_input_size,
                input_mac,
                input_iv,
                MAX_INPUT_OUTPUT_FILE_SIZE,
                output_buffer,
                &actual_output_size,
                output_mac,
                output_iv,
                &certificate.hash,
                &certificate.signature),
            &ecall_return_code)
            != 0) {
        if (ecall_return_code == HCV_SOURCE_USES_REGISTER_15) {
            return HCV_SOURCE_USES_REGISTER_15;
        } else {
            return 1;
        }
    }

    // write to the output meter file
    std::ofstream output_meter_file(output_meter_filename);

    if (!output_meter_file.good()) {
        std::cout << "Cannot open file " << output_meter_filename << "!" << std::endl;
        return SGX_ERROR_INVALID_PARAMETER;
    }
    output_meter_file.write(reinterpret_cast<char*>(output_buffer), actual_output_size);
    output_meter_file.close();

    std::cout << "Wrote " << input_filename << " that has " << actual_output_size << " bytes." << std::endl;

    // add public key to certificate
    if (hasgx_ensure_method_successful(
            "ecall_get_public_ca_key",
            ecall_get_public_ca_key(rewriter_enclave_id, &ecall_return_code,
                &certificate.public_key),
            &ecall_return_code)
            != 0) {
        std::cout << "========================" << std::endl;
        return 1;
    }

    std::cout << "> Metering and signing complete." << std::endl;
    std::cout << "> Contents of certificate:" << std::endl;
    hacert_print_certificate(&certificate);

    // output the certificate
    std::ofstream output_certificate_file(output_meter_filename + CERTIFICATE_FILENAME_SUFFIX);
    hafs_write_structure(&output_certificate_file, sizeof(certificate), reinterpret_cast<uint8_t*>(&certificate));
    output_certificate_file.close();
    std::cout << "> Write certificate to: " << output_meter_filename + CERTIFICATE_FILENAME_SUFFIX << std::endl;

    // ### console output: display result ###
    std::cout << "> Service Response: Success" << std::endl;
    std::cout << "========================" << std::endl;
    return 0;
}

int service_attestation_start(sgx_enclave_id_t rewriter_enclave_id,
        sgx_ec256_public_t client_public_key,
        sgx_ra_context_t* ra_context,
        sgx_ra_msg1_t* ra_msg1) {
    int32_t return_code;

    // ### console output: display input ###
    std::cout << "========================" << std::endl;
    std::cout << "> Service Request: Service attestation start" << std::endl;
    std::cout << "> " << std::endl;
    
    // ### run actual service ###
    if (hasgx_ensure_method_successful(
            "ecall_start_attestation",
            ecall_start_attestation(rewriter_enclave_id, &return_code,
                &client_public_key, 
                ra_context),
            &return_code)
            != 0) {
        return 1;
    }

    if (hasgx_ensure_method_successful(
            "sgx_ra_get_msg1",
            sgx_ra_get_msg1(
                *ra_context, 
                rewriter_enclave_id,
                &sgx_ra_get_ga, 
                ra_msg1))
            != 0) {
        return 1;
    }

    // ### console output: display result ###
    std::cout << "> Service Response: Success" << std::endl;
    std::cout << "========================" << std::endl;

    return 0;
}

int service_attestation_process_msg2(sgx_enclave_id_t rewriter_enclave_id,
        sgx_ra_context_t ra_context,
        sgx_ra_msg2_t* ra_msg2, sgx_ra_msg3_t** ra_msg3, uint32_t* ra_msg3_actual_size) {
    // ### console output: display input ###
    std::cout << "========================" << std::endl;
    std::cout << "> Service Request: Service attestation process msg2" << std::endl;
    std::cout << "> " << std::endl;

    // ### run actual service ###
    if (hasgx_ensure_method_successful(
            "sgx_ra_proc_msg2",
            sgx_ra_proc_msg2(ra_context, rewriter_enclave_id, 
                sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, 
                ra_msg2, sizeof(*ra_msg2) + 0,    // sig_rl is 0
                ra_msg3,
                ra_msg3_actual_size))
            != 0) {
        return 1;
    }
    
    // ### console output: display result ###
    std::cout << "> Service Response: Success" << std::endl;
    std::cout << "========================" << std::endl;

    return 0;
}

int service_attestation_finish(sgx_enclave_id_t rewriter_enclave_id,
        sgx_ra_context_t ra_context) {
    // ### console output: display input ###
    std::cout << "========================" << std::endl;
    std::cout << "> Service Request: Service attestation finish" << std::endl;
    std::cout << "> " << std::endl;

    int32_t return_code;

    // ### run actual service ###
    if (hasgx_ensure_method_successful(
            "ecall_finish_attestation",
            ecall_finish_attestation(rewriter_enclave_id, &return_code,
                ra_context),
            &return_code)
            != 0) {
        return 1;
    }

    // ### console output: display result ###
    std::cout << "> Service Response: Success" << std::endl;
    std::cout << "========================" << std::endl;

    return 0;
}

int handle_client_request(sgx_enclave_id_t rewriter_enclave_id, hans_NetServer* net_server, int client_fd) {
    struct server_attestation_function_pointers attest_funcs;
    attest_funcs.start_attestation = &service_attestation_start;
    attest_funcs.proc_msg2 = &service_attestation_process_msg2;
    attest_funcs.finish_attestation = &service_attestation_finish;

    // start attestation protocol
    if (haan_do_attestation_server(rewriter_enclave_id, net_server, client_fd, attest_funcs) != 0) {
        return 1;
    }

    std::cout << "Attestation complete! Continue with actual service..." << std::endl;

    // client: send service type
    int service_type = 0;
    if (!net_server->read_fixed(client_fd, sizeof(service_type), (uint8_t*)&service_type)) {
        return 1;
    }

    switch (service_type) {
        default:
            std::cout << "No code available to handle service " << service_type << std::endl;
            break;
        case 1:
            {
                std::cout << "Service 1 (meter writing) requested!" << std::endl;

                sgx_aes_gcm_128bit_tag_t input_mac;
                uint32_t content_size;
                uint8_t input_iv[IV_SIZE];

                // client: send input
                if (!net_server->read_fixed(client_fd, sizeof(input_iv), input_iv)) {
                    return 1;
                }
                if (!net_server->read_fixed(client_fd, sizeof(input_mac), input_mac)) {
                    return 1;
                }
                if (!net_server->read_fixed(client_fd, sizeof(content_size), (uint8_t*)&content_size)) {
                    return 1;
                }
                hca_CharArray input_encrypted_buffer(content_size);
                if (!net_server->read_fixed(client_fd, content_size, input_encrypted_buffer.array)) {
                    return 1;
                }

                std::cout << "Input received from client, processing..." << std::endl;

                hafs_make_dir("temp/");
                hafs_make_dir("temp/app_meterwriter/");
                const std::string INPUT_ENCRYPTED_FILENAME = "temp/app_meterwriter/input.enc.server";
                const std::string OUTPUT_METERED_ENCRYPTED_FILENAME = "temp/app_meterwriter/output.enc.server";

                hafs_write_buffer_to_file(INPUT_ENCRYPTED_FILENAME, content_size, input_encrypted_buffer.array);

                sgx_aes_gcm_128bit_tag_t output_mac;
                uint8_t output_iv[IV_SIZE];

                int meter_status = service_add_meter_and_sign(rewriter_enclave_id,
                        INPUT_ENCRYPTED_FILENAME, &input_mac, input_iv, 
                        OUTPUT_METERED_ENCRYPTED_FILENAME, &output_mac, output_iv);

                if (meter_status == HCV_SOURCE_USES_REGISTER_15) {
                    std::cout << std::endl;
                    std::cout << "Your source code uses %r15 in asm, which is forbidden." << std::endl;
                    std::cout << "Please recompile your code with %r15 reserved. In C++," << std::endl;
                    std::cout << "that is obtained by adding this as the first line:" << std::endl;
                    std::cout << std::endl;
                    std::cout << "    register int instruction_counter asm(\"r15\");" << std::endl;
                    std::cout << std::endl;
                }


                const std::string OUTPUT_CERTIFICATE_FILENAME = 
                        OUTPUT_METERED_ENCRYPTED_FILENAME + CERTIFICATE_FILENAME_SUFFIX;

                uint32_t output_content_size = hafs_get_file_size(OUTPUT_METERED_ENCRYPTED_FILENAME),
                    output_certificate_size = hafs_get_file_size(OUTPUT_CERTIFICATE_FILENAME);

                hca_CharArray output_encrypted_buffer(output_content_size);
                if (!hafs_read_file_to_buffer(OUTPUT_METERED_ENCRYPTED_FILENAME, output_content_size, 
                        output_encrypted_buffer.array)) {
                    return 1;
                }
                hca_CharArray output_certificate_buffer(output_certificate_size);
                if (!hafs_read_file_to_buffer(OUTPUT_CERTIFICATE_FILENAME, output_certificate_size,
                        output_certificate_buffer.array)) {
                    return 1;
                }


                // server: send output
                if (!net_server->write(client_fd, sizeof(meter_status), (uint8_t*)&meter_status)) {
                    return 1;
                }
                if (meter_status != 0) return 1;
                if (!net_server->write(client_fd, sizeof(output_iv), output_iv)) {
                    return 1;
                }
                if (!net_server->write(client_fd, sizeof(output_mac), output_mac)) {
                    return 1;
                }
                if (!net_server->write(client_fd, sizeof(output_content_size), (uint8_t*)&output_content_size)) {
                    return 1;
                }
                if (!net_server->write(client_fd, output_content_size, output_encrypted_buffer.array)) {
                    return 1;
                }
                if (!net_server->write(client_fd, sizeof(output_certificate_size), (uint8_t*)&output_certificate_size)) {
                    return 1;
                }
                if (!net_server->write(client_fd, output_certificate_size, output_certificate_buffer.array)) {
                    return 1;
                }

                std::cout << "Output sent to client!" << std::endl;
            }
            break;
        case 2:
            {
                std::cout << "Service 2 (public key verify) requested!" << std::endl;
                
                sgx_ec256_public_t public_key;

                // client: send public key
                if (!net_server->read_fixed(client_fd, sizeof(public_key), (uint8_t*)&public_key)) {
                    return 1;
                }

                // server: send response
                bool response_code;
                if (service_is_this_my_public_ca_key(rewriter_enclave_id, public_key, &response_code) != 0) {
                    return 1;
                }
                if (!net_server->write(client_fd, sizeof(response_code), (uint8_t*)&response_code)) {
                    return 1;
                }
                
                std::cout << "Public key response sent!" << std::endl;
            }
            break;
    }

    return 0;
}

int start_server(sgx_enclave_id_t rewriter_enclave_id, int server_port) {
    hans_NetServer net_server;
    
    std::srand(std::time(0));
    if (!net_server.init_with_port("app_meterwriter", server_port)) return 1;
    if (!net_server.start()) return 1;

    while (true) {
        std::cout << std::endl;
        std::cout << "Waiting for new client at " << server_port << "..." << std::endl;

        int client_fd = net_server.accept(nullptr);
        if (client_fd < 0) break;

        handle_client_request(rewriter_enclave_id, &net_server, client_fd);

        net_server.close_client(client_fd);

        std::cout << "Closed connection to client." << std::endl;
    }

    if (!net_server.close()) return 1;
    return 0;
}

int main(int argc, char** argv) {
    if (argc <= 1) {
        std::cout << "Usage: " << argv[0] << " [port]" << std::endl;
        return 1;
    }

    int server_port = std::atoi(argv[1]);
    sgx_enclave_id_t rewriter_enclave_id;

    // ### initialize service ##
    if (hasgx_create_enclave(&rewriter_enclave_id, "enclave_meterwriter.signed.so") != 0) {
        return 1;
    }

    if (initialize_rewriter_enclave(rewriter_enclave_id) != 0) {
        return 1;
    }

    // ### prepare for and handle service requests ###
    return start_server(rewriter_enclave_id, server_port);

    // for demo purpose, not in use otherwise
    //return demo_meterwriter(rewriter_enclave_id);
}
