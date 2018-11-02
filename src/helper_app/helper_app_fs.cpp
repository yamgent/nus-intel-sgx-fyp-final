#include "helper_app_fs.h"
#include <iostream>
#include "lib_crypto/lib_crypto_app.h"
#include <sys/stat.h>

// does file exist?
bool hafs_file_exist(std::string path) {
    return std::ifstream(path).good();
}

// write the size of the structure + content of the structure
void hafs_write_structure(std::ofstream* file, uint64_t structure_size, uint8_t* structure) {
    file->write(reinterpret_cast<const char*>(&structure_size), sizeof(structure_size));
    file->write(reinterpret_cast<const char*>(structure), structure_size);
}

// read the size of the structure + content of the structure
//
// NOTE: If buffer is not big enough, we will not read the entire content of the structure,
// but only read just enough for the buffer (in other words, the structure read in will be
// corrupted and should not be used, and the file pointer is now pointing to rubbish)
//
// Therefore, if buffer is not big enough, it should be considered as an error.
void hafs_read_structure(std::ifstream* file, uint64_t structure_buffer_size, 
        uint8_t* structure_buffer, uint64_t* actual_size) {
    file->read(reinterpret_cast<char*>(actual_size), sizeof(actual_size));
    file->read(reinterpret_cast<char*>(structure_buffer), 
        (structure_buffer_size < *actual_size) ? structure_buffer_size : *actual_size);
}

// encrypt a file using AES key
bool hafs_encrypt_file(std::string input_filename, std::string output_filename,
        sgx_cmac_128bit_tag_t* key, sgx_aes_gcm_128bit_tag_t* mac, uint8_t* iv,
        uint32_t* content_size) {

    uint8_t decrypted_buffer[MAX_INPUT_OUTPUT_FILE_SIZE], encrypted_buffer[MAX_INPUT_OUTPUT_FILE_SIZE];
        
    std::ifstream input_file(input_filename);
    if (!input_file.good()) { 
        std::cout << "Cannot read " << input_filename << "!" << std::endl; 
        return false; 
    }
    input_file.read(reinterpret_cast<char *>(decrypted_buffer), MAX_INPUT_OUTPUT_FILE_SIZE);
    *content_size = input_file.gcount();
    input_file.close();

    if (!lc_aes_encrypt(key, *content_size, decrypted_buffer, encrypted_buffer, IV_SIZE, iv, mac)) {
        std::cout << "Encryption failed!" << std::endl;
        return false;
    }

    std::ofstream output_file(output_filename);
    if (!output_file.good()) {
        std::cout << "Cannot open " << output_filename << "!" << std::endl;
        return false;
    }
    output_file.write(reinterpret_cast<char *>(encrypted_buffer), *content_size);
    output_file.close();
    return true;
}

// decrypt a file using AES key
bool hafs_decrypt_file(std::string input_filename, std::string output_filename,
        sgx_cmac_128bit_tag_t* key, sgx_aes_gcm_128bit_tag_t* mac, uint8_t* iv,
        uint32_t* content_size) {

    uint8_t decrypted_buffer[MAX_INPUT_OUTPUT_FILE_SIZE], encrypted_buffer[MAX_INPUT_OUTPUT_FILE_SIZE];
        
    std::ifstream input_file(input_filename);
    if (!input_file.good()) { 
        std::cout << "Cannot read " << input_filename << "!" << std::endl; 
        return false; 
    }
    input_file.read(reinterpret_cast<char *>(encrypted_buffer), MAX_INPUT_OUTPUT_FILE_SIZE);
    *content_size = input_file.gcount();
    input_file.close();

    if (!lc_aes_decrypt(key, *content_size, encrypted_buffer, decrypted_buffer, IV_SIZE, iv, mac)) {
        std::cout << "Decryption failed!" << std::endl;
        return false;
    }

    std::ofstream output_file(output_filename);
    if (!output_file.good()) {
        std::cout << "Cannot open " << output_filename << "!" << std::endl;
        return false;
    }
    output_file.write(reinterpret_cast<char *>(decrypted_buffer), *content_size);
    output_file.close();
    return true;
}

// what is the file size of the file
uint64_t hafs_get_file_size(std::string filename) {
    struct stat file_stat;

    if (stat(filename.c_str(), &file_stat) < 0) {
        std::cout << "Fail to obtain file size of " << filename << "! Error: " << errno << std::endl;
        return 0;
    }

    return file_stat.st_size;
}

// write the buffer's content to file (content size will be buffer_size)
bool hafs_write_buffer_to_file(std::string filename, uint64_t buffer_size, uint8_t* buffer) {
    std::ofstream file(filename);

    if (!file.good()) {
        std::cout << "Cannot open file for writing " << filename << std::endl;
        return false;
    }

    file.write(reinterpret_cast<char *>(buffer), buffer_size);
    file.close();

    return true;
}

// read the file content's to buffer (we either finish reading everything, or if the buffer
// does not have enough space, fill the buffer to full but incomplete)
bool hafs_read_file_to_buffer(std::string filename, uint64_t buffer_size, uint8_t* buffer) {

    std::ifstream file(filename);

    if (!file.good()) {
        std::cout << "Cannot open file for reading " << filename << std::endl;
        return false;
    }

    file.read(reinterpret_cast<char *>(buffer), buffer_size);
    file.close();

    return true;
}

bool hafs_make_dir(std::string directory_path) {
    int return_code;

    return_code = mkdir(directory_path.c_str(), S_IRWXU); // S_IRWXU: rwx for user

    if (return_code == -1) {
        if (errno == EEXIST) {
            // already exist, there's no need to create it again!
            return true;
        }

        std::cout << "Cannot create directory " << directory_path << "!" << std::endl;
        return false;
    }

    return true;
}
