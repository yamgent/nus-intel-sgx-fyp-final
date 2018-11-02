#include "helper_common_meter_logic.h"
#include "helper_common_bufferio.h"
#include "helper_common_meter.h"
#include "helper_common_values.h"
#include <queue>

// write line to a buffer and do SHA-256 hashing
int32_t hcml_write_line_to_buffer_and_sha256hash(
        hcbio_StringWriter* writer,
        std::string output_line,
        SHA256_CTX* sha256_ctx) {

    int32_t return_code;

    // write
    writer->write_line(output_line);

    // hash
    return_code = hash_update(sha256_ctx, reinterpret_cast<const uint8_t*>(output_line.c_str()),
        output_line.size());
    if (return_code != RET_SUCCESS) return return_code;

    return_code = hash_update(sha256_ctx, reinterpret_cast<const uint8_t*>("\n"),
        1);
    if (return_code != RET_SUCCESS) return return_code;

    return RET_SUCCESS;
}

// main logic for adding metering and generating hash
int32_t hcml_add_meter_and_generate_hash(
    uint64_t input_buffer_size, uint8_t* input_buffer, uint64_t actual_input_size,
    uint64_t output_buffer_size, uint8_t* output_buffer, uint64_t* actual_output_size,
    SHA256_HASH* output_hash) {

    int32_t return_code;

    // initialize readers and writers
    hcbio_StringReader reader1(input_buffer, actual_input_size);
    hcbio_StringReader reader2(input_buffer, actual_input_size);
    hcbio_StringWriter writer(output_buffer, output_buffer_size);

    // initialize hash
    SHA256_CTX sha_state_handle;
    return_code = hash_init(&sha_state_handle);
    if (return_code != RET_SUCCESS) return return_code;

    std::queue<int32_t> total_instructions_for_label;

    // pass 1: count total instructions for each label
    {
        int32_t label_instructions_count = 0;
        std::string current_line = reader1.read_line();

        while(!reader1.eof() || current_line != "") {
            if (hcmtr_is_label(current_line)) {
                total_instructions_for_label.push(label_instructions_count);
                label_instructions_count = 0;
            } else {
                if (hcmtr_is_instruction(current_line)) {
                    if (hcmtr_instruction_uses_r15(current_line)) {
                        // illegal use of register 15 is forbidden
                        return HCV_SOURCE_USES_REGISTER_15;
                    }

                    label_instructions_count++;
                }
            }

            current_line = reader1.read_line();
        }

        // the last label needs to be pushed!
        total_instructions_for_label.push(label_instructions_count);

        // the start of the file has no label!
        total_instructions_for_label.pop();
    }

    // pass 2: output the correct metering instructions with the correct count, and
    // do hashing along the way
    {
        int32_t label_instructions_count = 0;
        bool label_found = false;

        std::string current_line = reader2.read_line();

        while(!reader2.eof() || current_line != "") {            
            if (hcmtr_is_label(current_line)) {
                label_found = true;
                label_instructions_count = total_instructions_for_label.front();
                total_instructions_for_label.pop();
            } else if (label_found) {
                if (hcmtr_is_instruction(current_line)) {
                    std::string meter_instruction = 
                        "    leaq    " + std::to_string(label_instructions_count) +
                        "(%r15), %r15       # meter instruction";

                    return_code = 
                        hcml_write_line_to_buffer_and_sha256hash(&writer, 
                                                            meter_instruction, &sha_state_handle);
                    if (return_code != RET_SUCCESS) return return_code;
                    
                    label_found = false;
                }
            }

            return_code = hcml_write_line_to_buffer_and_sha256hash(&writer, 
                                                                current_line, &sha_state_handle);
            if (return_code != RET_SUCCESS) return return_code;

            current_line = reader2.read_line();
        }
    }

    // compute hash
    return_code = hash_get(&sha_state_handle, output_hash);
    if (return_code != RET_SUCCESS) return return_code;
    return_code = hash_close(&sha_state_handle);
    if (return_code != RET_SUCCESS) return return_code;

    // close readers and writers
    *actual_output_size = writer.close();
    reader2.close();
    reader1.close();

    return RET_SUCCESS;
}
