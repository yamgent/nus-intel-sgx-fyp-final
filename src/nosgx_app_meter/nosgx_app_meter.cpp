#include <iostream>
#include <queue>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include "helper_common/helper_common_meter_logic.h"
#include "helper_common/helper_common_interface_sha256.h"
#include <iomanip>

uint64_t get_file_size(std::string filename) {
    struct stat file_stat;

    if (stat(filename.c_str(), &file_stat) < 0) {
        std::cout << "Fail to obtain file size of " << filename << "! Error: " << errno << std::endl;
        return 0;
    }

    return file_stat.st_size;
}

int process_source(std::string input_file_name, std::string output_file_name) {
    // read in file content
    uint64_t input_file_size = get_file_size(input_file_name);
    if (input_file_size == 0) {
        return 1;
    }

    std::ifstream input_file(input_file_name, std::ifstream::binary);
    if (!input_file.good()) {
        std::cout << "File " << input_file_name << " cannot be read or does not exist." << std::endl;
        return 1;
    }

    uint8_t* input_buffer = new uint8_t[input_file_size];
    input_file.read((char *)input_buffer, input_file_size);
    input_file.close();

    // prepare output buffer
    uint64_t output_buffer_size = input_file_size + 10000;
    uint8_t* output_buffer = new uint8_t[output_buffer_size];
    uint64_t actual_output_size = 0;

    SHA256_HASH output_hash;
    if (hcml_add_meter_and_generate_hash(input_file_size, input_buffer, input_file_size,
        output_buffer_size, output_buffer, &actual_output_size, &output_hash) != RET_SUCCESS) {
        
        std::cout << "Fail to add meter properly" << std::endl;
    }

    // print hash
    std::cout << "Hash: ";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)output_hash[i];
    }
    std::cout << std::endl;
    std::cout << std::dec;

    // write to file
    std::ofstream output_file(output_file_name, std::ofstream::binary);
    if (!output_file.good()) {
        std::cout << "File " << output_file_name << " cannot be written." << std::endl;
        return 1;
    }

    output_file.write((char*)output_buffer, actual_output_size);
    output_file.close();

    // clean up
    delete[] output_buffer;
    delete[] input_buffer;

    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " [input] [output]" << std::endl;
        return 0;
    }

    return process_source(argv[1], argv[2]);
}
