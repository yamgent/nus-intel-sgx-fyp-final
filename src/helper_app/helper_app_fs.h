#ifndef HELPER_APP_FS_H
#define HELPER_APP_FS_H

#include <string>
#include <fstream>
#include "sgx_tcrypto.h"
#include "helper_common/helper_common_values.h"

#define MAX_INPUT_OUTPUT_FILE_SIZE 20000

bool hafs_file_exist(std::string path);

void hafs_write_structure(std::ofstream* file, uint64_t structure_size, uint8_t* structure);

void hafs_read_structure(std::ifstream* file, uint64_t structure_buffer_size, 
        uint8_t* structure_buffer, uint64_t* actual_size);

bool hafs_encrypt_file(std::string input_filename, std::string output_filename,
        sgx_cmac_128bit_tag_t* key, sgx_aes_gcm_128bit_tag_t* mac, uint8_t* iv,
        uint32_t* content_size);

bool hafs_decrypt_file(std::string input_filename, std::string output_filename,
        sgx_cmac_128bit_tag_t* key, sgx_aes_gcm_128bit_tag_t* mac, uint8_t* iv,
        uint32_t* content_size);

uint64_t hafs_get_file_size(std::string filename);

bool hafs_write_buffer_to_file(std::string filename, uint64_t buffer_size, uint8_t* buffer);
bool hafs_read_file_to_buffer(std::string filename, uint64_t buffer_size, uint8_t* buffer);

bool hafs_make_dir(std::string directory_path);

#endif
