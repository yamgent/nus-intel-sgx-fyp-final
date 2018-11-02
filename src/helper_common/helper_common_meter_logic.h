#ifndef HELPER_COMMON_METER_LOGIC_H
#define HELPER_COMMON_METER_LOGIC_H

#include "helper_common/helper_common_interface_sha256.h"

int32_t hcml_add_meter_and_generate_hash(
    uint64_t input_buffer_size, uint8_t* input_buffer, uint64_t actual_input_size,
    uint64_t output_buffer_size, uint8_t* output_buffer, uint64_t* actual_output_size,
    SHA256_HASH* output_hash);

#endif
