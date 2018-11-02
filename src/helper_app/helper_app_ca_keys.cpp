#include "helper_app_ca_keys.h"
#include "sgx_tseal.h"

#include "helper_app/helper_app_fs.h"
#include "helper_app/helper_app_sgx.h"
#include "helper_common/helper_common_array.h"
#include <iostream>

int32_t hack_load_ca_keys(
    sgx_enclave_id_t enclave_id,
    std::string keypair_filename,
    hack_keypair_management_functions methods) {

    // generate new keypair if we don't have existing ones
    if (!hafs_file_exist(keypair_filename)) {
        uint8_t sealed_data_buffer[1000];
        uint64_t actual_sealed_size;
        int32_t ecall_return_code;

        if (hasgx_ensure_method_successful(
                methods.generate_pair_method_name,
                methods.generate_pair_method(enclave_id, &ecall_return_code,
                    sizeof(sealed_data_buffer), sealed_data_buffer,
                    &actual_sealed_size),
                &ecall_return_code)
                != 0) {
            return 1;
        }

        if (!hafs_write_buffer_to_file(keypair_filename, actual_sealed_size, sealed_data_buffer)) {
            return 1;
        }
        std::cout << "No " << keypair_filename << " found so generating new keypair..." << std::endl;
    } else {
        uint64_t sealed_key_buffer_size = hafs_get_file_size(keypair_filename);
        if (sealed_key_buffer_size < 0) {
            std::cout << "Cannot load " << keypair_filename << "!" << std::endl;
            return 1;
        }

        hca_CharArray sealed_key_buffer(sealed_key_buffer_size);
        hafs_read_file_to_buffer(keypair_filename, sealed_key_buffer_size, sealed_key_buffer.array);

        int32_t ecall_return_code;

        if (hasgx_ensure_method_successful(
                methods.load_pair_method_name,
                methods.load_pair_method(enclave_id, &ecall_return_code,
                    sealed_key_buffer_size, sealed_key_buffer.array),
                &ecall_return_code)
                != 0) {
            return 1;
        }

        std::cout << "CA keypair '" << keypair_filename << "' loaded!" << std::endl;
    }
    return 0;
}
