#include "helper_app_fileio.h"
#include <cstring>
#include <iostream>

std::ifstream g_readers[HAFIO_MAX_READER_HANDLES];
std::ofstream g_writers[HAFIO_MAX_WRITER_HANDLES];

bool hafio_is_reader_handle_in_range(int reader_handle) {
    return reader_handle >= 0 && reader_handle < HAFIO_MAX_READER_HANDLES;
}

bool hafio_is_writer_handle_in_range(int writer_handle) {
    return writer_handle >= 0 && writer_handle < HAFIO_MAX_WRITER_HANDLES;
}

// if file does not exist, it may be NOT good.
bool hafio_is_reader_good(std::ifstream* reader) {
    return reader != nullptr && reader->good();
}

// if file is protected, it may be NOT good.
bool hafio_is_writer_good(std::ofstream* writer) {
    return writer != nullptr && writer->good();
}

std::ifstream* hafio_get_reader(int reader_handle) {
    if (!hafio_is_reader_handle_in_range(reader_handle)) {
        return nullptr;
    }
    return &g_readers[reader_handle];
}

std::ofstream* hafio_get_writer(int writer_handle) {
    if (!hafio_is_writer_handle_in_range(writer_handle)) {
        return nullptr;
    }

    return &g_writers[writer_handle];
}

void ocall_hafio_read_line(int reader_handle, uint64_t line_buffer_size, char* line_buffer) {
    std::ifstream* reader = hafio_get_reader(reader_handle);
    if (!hafio_is_reader_good(reader)) return;

    std::string temp;
    std::getline(*reader, temp);

    if (line_buffer_size < temp.length()) {
        std::cout << "Programmer Error: ocall_hafio_read_line() must have enough buffer size!" << std::endl;
        return;
    }

    strcpy(line_buffer, temp.c_str());
}

// have we reached the end of file yet?
// returns 1 if yes, 0 if no
int ocall_hafio_read_eof(int reader_handle) {
    std::ifstream* reader = hafio_get_reader(reader_handle);
    if (!hafio_is_reader_good(reader)) return 1;

    return reader->eof() ? 1 : 0;
}

void ocall_hafio_write_line(int writer_handle, const char* line_to_write) {
    std::ofstream* writer = hafio_get_writer(writer_handle);
    if (!hafio_is_writer_good(writer)) return;

    (*writer) << line_to_write << std::endl;
}
