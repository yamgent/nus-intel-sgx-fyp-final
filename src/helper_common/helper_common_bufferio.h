#ifndef HELPER_COMMON_BUFFERIO_H
#define HELPER_COMMON_BUFFERIO_H

#include <string>

#define HCBIO_EOF '\0'

// a buffer string reader, each line must end with a '\n', and 
// the entire buffer must end with a '\0' (recognized as EOF)
class hcbio_StringReader {
private:
    uint8_t* buffer;
    uint32_t buffer_size;
    uint32_t current_pointer;

    bool is_closed;
    bool eof_hit;
public:
    hcbio_StringReader(uint8_t* buffer, uint32_t buffer_size);
    ~hcbio_StringReader();

    std::string read_line();
    bool eof();
    uint32_t close();

    bool is_it_closed();
};

// a buffer string writer, each line will end with a '\n', and 
// the entire buffer will end with a '\0' (recognized as EOF)
class hcbio_StringWriter {
private:
    uint8_t* buffer;
    uint32_t buffer_size;
    uint32_t current_pointer;

    bool is_closed;
public:
    hcbio_StringWriter(uint8_t* buffer, uint32_t buffer_size);
    ~hcbio_StringWriter();

    bool write_line(std::string line);
    uint32_t close();

    bool is_it_closed();
};

#endif
