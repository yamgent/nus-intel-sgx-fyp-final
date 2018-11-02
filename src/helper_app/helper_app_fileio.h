#ifndef HELPER_APP_FILEIO_H
#define HELPER_APP_FILEIO_H

#include <fstream>

#define HAFIO_MAX_READER_HANDLES 10
#define HAFIO_MAX_WRITER_HANDLES 10

std::ifstream* hafio_get_reader(int reader_handle);

std::ofstream* hafio_get_writer(int writer_handle);


extern "C" {
    void ocall_hafio_read_line(int reader_handle, uint64_t line_buffer_size, char* line_buffer);
    int ocall_hafio_read_eof(int reader_handle);

    void ocall_hafio_write_line(int writer_handle, const char* line_to_write);
}

#endif
