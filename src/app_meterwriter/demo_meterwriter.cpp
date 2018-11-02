#include "demo_meterwriter.h"

#include "app_meterwriter.h"

#include <iostream>
#include "lib_crypto/lib_crypto_app.h"
#include "helper_app/helper_app_attest.h"
#include "helper_app/helper_app_fs.h"
#include "helper_app/helper_app_cert.h"
#include "helper_app/helper_app_sgx.h"
#include "helper_common/helper_common_values.h"
#include <cstring>

// wait for Return key
void pause() {
    std::string unused;
    std::getline(std::cin, unused);
}

// this file is the non-network demo version of app_meterwriter
// usage

int demo_meterwriter(sgx_enclave_id_t rewriter_enclave_id) {
    sgx_cmac_128bit_tag_t shared_session_key;

    pause();
    {
        if (!lc_init()) {
            std::cout << "Fail to initialize lib_crypto!" << std::endl;
            return 1;
        }

        // start attestation process
        sgx_ra_context_t ra_context;
        haa_Attestor attestor;
        if (!attestor.generate_key_pair()) {
            return 1;
        }

        // get msg1
        sgx_ra_msg1_t ra_msg1;
        if (service_attestation_start(rewriter_enclave_id, 
                attestor.get_my_public_key(), &ra_context, &ra_msg1) != 0) {
            return 1;
        }

        // make msg2
        sgx_ra_msg2_t* ra_msg2;
        uint32_t ra_msg2_actual_size;
        if (!attestor.process_msg1(ra_msg1, &ra_msg2, &ra_msg2_actual_size)) {
            return 1;
        }

        // get msg3
        sgx_ra_msg3_t* ra_msg3;
        uint32_t ra_msg3_actual_size;
        if (service_attestation_process_msg2(rewriter_enclave_id, ra_context,
                ra_msg2, &ra_msg3, &ra_msg3_actual_size) != 0) {
            return 1;
        }
        free(ra_msg2);

        // verify msg3
        if (!attestor.process_msg3(ra_msg3, ra_msg3_actual_size)) {
            return 1;
        }
        free(ra_msg3);

        // get the shared session key
        if (!attestor.get_shared_session_key(&shared_session_key)) {
            return 1;
        }

        if (service_attestation_finish(rewriter_enclave_id, ra_context) != 0) {
            return 1;
        }
    }
    pause();

    const std::string INPUT_FILENAME = "test_source.s";
    const std::string OUTPUT_METERED_FILENAME = "test_source_metered.s";

    const std::string INPUT_ENCRYPTED_FILENAME = "test_source.s.encrypted";
    const std::string OUTPUT_METERED_ENCRYPTED_FILENAME = "test_source_metered.s.encrypted";

    {
        sgx_aes_gcm_128bit_tag_t input_mac, output_mac;
        uint32_t content_size;
        uint8_t input_iv[IV_SIZE], output_iv[IV_SIZE];

        if (!lc_rand(IV_SIZE, input_iv)) {
            std::cout << "Calling lc_rand() failed!" << std::endl;
            return 1;
        }

        if (!hafs_encrypt_file(INPUT_FILENAME, INPUT_ENCRYPTED_FILENAME,
                &shared_session_key, &input_mac, input_iv, &content_size)) {
            return 1;
        }

        int meter_status = service_add_meter_and_sign(rewriter_enclave_id,
                INPUT_ENCRYPTED_FILENAME, &input_mac, input_iv, 
                OUTPUT_METERED_ENCRYPTED_FILENAME, &output_mac, output_iv);
        if (meter_status != 0) {
            if (meter_status == HCV_SOURCE_USES_REGISTER_15) {
                std::cout << std::endl;
                std::cout << "Your source code uses %r15 in asm, which is forbidden." << std::endl;
                std::cout << "Please recompile your code with %r15 reserved. In C++," << std::endl;
                std::cout << "that is obtained by adding this as the first line:" << std::endl;
                std::cout << std::endl;
                std::cout << "    register int instruction_counter asm(\"r15\");" << std::endl;
                std::cout << std::endl;
            }
            return 1;
        }

        if (!hafs_decrypt_file(OUTPUT_METERED_ENCRYPTED_FILENAME, OUTPUT_METERED_FILENAME,
                &shared_session_key, &output_mac, output_iv, &content_size)) {
            return 1;
        }
    }
    pause();
    {
        hacert_metered_code_certificate certificate;

        // open certificate
        std::ifstream certificate_file(OUTPUT_METERED_ENCRYPTED_FILENAME + CERTIFICATE_FILENAME_SUFFIX, 
            std::ifstream::binary);
        uint64_t ignore_actual_size;
        hafs_read_structure(&certificate_file, 
            sizeof(certificate), reinterpret_cast<uint8_t*>(&certificate), &ignore_actual_size);

        // verify hash in certificate
        sgx_sha256_hash_t computed_hash;
        if (!lc_sha256_file_hash(OUTPUT_METERED_FILENAME, &computed_hash)) {
            std::cout << "Fail to compute hash of " << OUTPUT_METERED_FILENAME << "!" << std::endl;
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

        // verifiy public key in certificate
        bool response_code;
        service_is_this_my_public_ca_key(rewriter_enclave_id, certificate.public_key, &response_code);
        if (!response_code) {
            std::cout << "Public key is NOT from the enclave! :(" << std::endl;
            return 1;
        } else {
            std::cout << "Public key verified from enclave!" << std::endl;
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

    return 0;
}
