#include "helper_common_bufferio.h"

hcbio_StringReader::hcbio_StringReader(uint8_t* buffer, uint32_t buffer_size) {
    this->buffer = buffer;
    this->buffer_size = buffer_size;
    this->current_pointer = 0;
    this->is_closed = false;
    this->eof_hit = false;
}

hcbio_StringReader::~hcbio_StringReader() {
    if (!is_closed) {
        close();
    }
}

std::string hcbio_StringReader::read_line() {
    if (is_closed) {
        return "";
    }
    if (eof()) {
        return "";
    }

    const int MAX_LINE_LENGTH_ALLOWED = 300;
    char output_buffer[MAX_LINE_LENGTH_ALLOWED];

    for (int i = 0; i < MAX_LINE_LENGTH_ALLOWED; i++) {
        if (current_pointer >= buffer_size) {
            eof_hit = true;
            output_buffer[i] = '\0';
            break;
        }

        char curr_char = buffer[current_pointer++];

        if (curr_char == HCBIO_EOF) {
            eof_hit = true;
            output_buffer[i] = '\0';
            break;
        }

        if (curr_char == '\n' || i == MAX_LINE_LENGTH_ALLOWED - 1) {
            output_buffer[i] = '\0';
            break;
        }

        output_buffer[i] = curr_char;
    }

    return std::string(output_buffer);
}

bool hcbio_StringReader::eof() {
    if (is_closed) {
        return true;
    }

    if (buffer[current_pointer] == HCBIO_EOF ||
            current_pointer >= buffer_size) {
        eof_hit = true;
    }

    return eof_hit;
}

// returns the number of bytes read
uint32_t hcbio_StringReader::close() {
    if (is_closed) {
        return current_pointer;
    }

    is_closed = true;
    return current_pointer;
}

bool hcbio_StringReader::is_it_closed() {
    return is_closed;
}

hcbio_StringWriter::hcbio_StringWriter(uint8_t* buffer, uint32_t buffer_size) {
    this->buffer = buffer;
    this->buffer_size = buffer_size;
    this->current_pointer = 0;
    this->is_closed = false;
}

hcbio_StringWriter::~hcbio_StringWriter() {
    if (!is_closed) {
        close();
    }
}

bool hcbio_StringWriter::write_line(std::string line) {
    if (is_closed) {
        return false;
    }

    if (current_pointer + line.size() + 1 >= buffer_size) {
        // not enough space
        return false;
    }

    for (int i = 0; i < line.size(); i++) {
        buffer[current_pointer++] = line[i];
    }
    buffer[current_pointer++] = '\n';

    return true;
}

// return number of bytes written (excluding \0 = HCBIO_EOF)
uint32_t hcbio_StringWriter::close() {
    if (is_closed) {
        return current_pointer;
    }

    if (current_pointer >= buffer_size) {
        current_pointer = buffer_size - 1;
    }

    buffer[current_pointer] = HCBIO_EOF;
    is_closed = true;
    return current_pointer;
}

bool hcbio_StringWriter::is_it_closed() {
    return is_closed;
}
