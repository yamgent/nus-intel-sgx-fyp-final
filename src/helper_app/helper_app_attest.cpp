#include "helper_app_attest.h"

#include "lib_crypto/lib_crypto_app.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

// simulated intel attestation API
intel_attestation_report send_quote_to_intel(uint32_t data_size, uint8_t* data) {
    struct intel_attestation_report result;
    result.measurement_correct = (data_size > 0 && data != nullptr);

    return result;
}

haa_Attestor::haa_Attestor() {
    this->attest_complete = false;
}

// generate a keypair for my attestor side
bool haa_Attestor::generate_key_pair() {
    if (!lc_create_ecc_keypair(&my_private_key, &my_public_key)) {
        std::cout << "Call to lc_create_ecc_keypair() failed!" << std::endl;
        return false;
    }

    return true;
}

// get my public key
sgx_ec256_public_t haa_Attestor::get_my_public_key() {
    return my_public_key;
}

// process msg1 and generate msg2
bool haa_Attestor::process_msg1(sgx_ra_msg1_t ra_msg1, sgx_ra_msg2_t** ra_msg2, uint32_t* ra_msg2_size) {
    *ra_msg2_size = sizeof(sgx_ra_msg2_t);
    *ra_msg2 = reinterpret_cast<sgx_ra_msg2_t *>(malloc(sizeof(sgx_ra_msg2_t)));

    memcpy(&their_public_key, &ra_msg1.g_a, sizeof(sgx_ec256_public_t));

    if (!lc_ecc_compute_shared_dhkey(my_private_key, their_public_key, &shared_ecc_dh_key)) {
        std::cout << "Call to lc_ecc_compute_shared_dhkey() failed!" << std::endl;
        return false;
    }

    memcpy(&(*ra_msg2)->g_b, &my_public_key, sizeof((*ra_msg2)->g_b));
    memset(&(*ra_msg2)->spid, 0, sizeof((*ra_msg2)->spid));
    (*ra_msg2)->quote_type = 1; // linkable quote
    (*ra_msg2)->kdf_id = 1; // SAMPLE_AES_CMAC_KDF_ID

    uint8_t g_b_g_a[sizeof(sgx_ec256_public_t) * 2];
    memcpy(g_b_g_a,                              &my_public_key,    sizeof(sgx_ec256_public_t));
    memcpy(g_b_g_a + sizeof(sgx_ec256_public_t), &their_public_key, sizeof(sgx_ec256_public_t));
    sgx_ec256_signature_t g_b_g_a_signature;
    if (!lc_ecdsa_sign(sizeof(g_b_g_a), g_b_g_a, my_private_key, &g_b_g_a_signature)) {
        std::cout << "lc_ecdsa_sign() failed!" << std::endl;
        return false;
    }
    memcpy(&(*ra_msg2)->sign_gb_ga, &g_b_g_a_signature, sizeof((*ra_msg2)->sign_gb_ga));

    // ##### MAC (start) #####

    sgx_cmac_128bit_key_t kdk_key = { 0 };
    if (!lc_aes_cmac(&kdk_key, sizeof(shared_ecc_dh_key), reinterpret_cast<uint8_t *>(&shared_ecc_dh_key), &kdk)) {
        std::cout << "Fail to generate kdk!" << std::endl;
        return false;
    }

    uint8_t smk_content[] = { 0x01, 'S', 'M', 'K', 0x00, 0x80, 0x00 };
    if (!lc_aes_cmac(&kdk, sizeof(smk_content), smk_content, &smk)) {
        std::cout << "Fail to generate smk!" << std::endl;
        return false;
    }

    uint32_t signed_message_size = sizeof(sgx_ec256_public_t) + sizeof(sgx_spid_t) + 
                sizeof(uint16_t) + sizeof(uint16_t) + sizeof(sgx_ec256_signature_t);
    if (!lc_aes_cmac(&smk, signed_message_size, reinterpret_cast<uint8_t *>(*ra_msg2), &(*ra_msg2)->mac)) {
        std::cout << "Fail to sign msg2!" << std::endl;
        return false;
    }

    // ##### MAC (end) #####

    // (*ra_msg2)->sig_rl;     // we are not using this
    (*ra_msg2)->sig_rl_size = 0;
    return true;
}

// process msg3 (verification) and generate shared session key
bool haa_Attestor::process_msg3(sgx_ra_msg3_t* ra_msg3, uint32_t ra_msg3_size) {

    sgx_cmac_128bit_tag_t my_mac;
    if (!lc_aes_cmac(&smk, ra_msg3_size - sizeof(sgx_mac_t), 
            reinterpret_cast<uint8_t*>(&ra_msg3->g_a), &my_mac)) {
        std::cout << "Fail to generate MAC from msg3!" << std::endl;
        return false;
    }
    if (memcmp(&ra_msg3->mac, &my_mac, sizeof(my_mac) != 0)) {
        std::cout << "MAC comparison failed." << std::endl;
        return false;
    }

    if (memcmp(&ra_msg3->g_a, &their_public_key, sizeof(sgx_ec256_public_t)) != 0) {
        std::cout << "Enclave public key (g_a) comparison failed." << std::endl;
        return false;
    }

    sgx_ps_sec_prop_desc_t sec_prop = { 0 }; // Intel say if Platform Service not required (simulation), 
                                             // all will be 0
    if (memcmp(&ra_msg3->ps_sec_prop, &sec_prop, sizeof(sec_prop)) != 0) {
        std::cout << "Sec prop comparison failed." << std::endl;
        return false;
    }

    struct intel_attestation_report attestation_report = send_quote_to_intel(
        (ra_msg3_size - sizeof(sgx_mac_t) - sizeof(sgx_ec256_public_t) - sizeof(sgx_ps_sec_prop_desc_t)),
        ra_msg3->quote);

    if (!attestation_report.measurement_correct) {
        std::cout << "Quote report verification failed." << std::endl;
        return false;
    }

    uint8_t sk_content[] = { 0x01, 'S', 'K', 0x00, 0x80, 0x00 };
    if (!lc_aes_cmac(&kdk, sizeof(sk_content), sk_content, &shared_session_key)) {
        std::cout << "Fail to generate session key!" << std::endl;
        return false;
    }

    attest_complete = true;

    return true;
}

// NOTE: Only call this after msg3 is verified!
bool haa_Attestor::get_shared_session_key(sgx_cmac_128bit_tag_t* session_key) {
    if (!attest_complete) {
        return false;
    }

    memcpy(session_key, &this->shared_session_key, sizeof(sgx_cmac_128bit_tag_t));
    return true;
}
