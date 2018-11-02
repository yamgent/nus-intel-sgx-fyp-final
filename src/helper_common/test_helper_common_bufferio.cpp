#include <assert.h>
#include "helper_enclave_bufferio.h"
#include <cstring>
#include <iostream>

int main(int argc, char** argv) {
    uint8_t read_buffer[] = "This is\na sample\nbuffer\0";

    // normal read
    {
        hebio_StringReader reader(read_buffer, sizeof(read_buffer));
        assert(reader.is_it_closed() == false);
        assert(reader.eof() == false);
        assert(reader.read_line() == "This is");
        assert(reader.is_it_closed() == false);
        assert(reader.eof() == false);
        assert(reader.read_line() == "a sample");
        assert(reader.is_it_closed() == false);
        assert(reader.eof() == false);
        assert(reader.read_line() == "buffer");

        // read exhaustively
        assert(reader.is_it_closed() == false);
        assert(reader.eof() == true);
        assert(reader.read_line() == "");

        assert(reader.close() == sizeof(read_buffer) - 1);
        assert(reader.is_it_closed() == true);
        assert(reader.eof() == true);
        assert(reader.read_line() == "");
    }
    
    // did not read finish
    {
        hebio_StringReader reader2(read_buffer, sizeof(read_buffer));
        reader2.read_line();
        assert(reader2.is_it_closed() == false);
        assert(reader2.eof() == false);
        
        assert(reader2.close() == 8);
        assert(reader2.is_it_closed() == true);
        assert(reader2.eof() == true);
        assert(reader2.read_line() == "");
    }

    // buffer so small it did not hit HEBIO_EOF (\0)
    {
        hebio_StringReader reader3(read_buffer, 2);
        assert(reader3.is_it_closed() == false);
        assert(reader3.eof() == false);
        assert(reader3.read_line() == "Th");
        assert(reader3.is_it_closed() == false);
        assert(reader3.eof() == true);
        assert(reader3.read_line() == "");

        assert(reader3.close() == 2);
        assert(reader3.is_it_closed() == true);
        assert(reader3.eof() == true);
        assert(reader3.read_line() == "");
    }

    const int MAX_BUFFER_SIZE = 100;
    uint8_t write_buffer[MAX_BUFFER_SIZE] = { 0 };
    uint8_t expected_write_buffer[] = "Some final\ncontent written by\nWriter!\n\0";
    uint32_t expected_length = strlen(reinterpret_cast<char*>(expected_write_buffer));

    // normal write
    {
        hebio_StringWriter writer(write_buffer, sizeof(write_buffer));
        assert(writer.is_it_closed() == false);
        assert(writer.write_line("Some final") == true);
        assert(writer.is_it_closed() == false);
        assert(writer.write_line("content written by") == true);
        assert(writer.is_it_closed() == false);
        assert(writer.write_line("Writer!") == true);
        assert(writer.is_it_closed() == false);
        assert(writer.close() == expected_length);
        assert(writer.is_it_closed() == true);
        assert(writer.write_line("This should not appear") == false);

        for (int i = 0; i < expected_length; i++) {
            assert(write_buffer[i] == expected_write_buffer[i]);
        }
        for (int i = expected_length; i < MAX_BUFFER_SIZE; i++) {
            assert(write_buffer[i] == '\0');
        }
    }

    memset(write_buffer, 0, sizeof(write_buffer));
    // write too much
    {
        std::string too_long = std::string("AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|") +
                std::string("AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|AAAAAAAAA|");
        
        hebio_StringWriter writer2(write_buffer, sizeof(write_buffer));
        assert(writer2.is_it_closed() == false);
        assert(writer2.write_line(too_long) == false);
        assert(writer2.is_it_closed() == false);
        assert(writer2.write_line("Abc") == true);
        assert(writer2.is_it_closed() == false);
        assert(writer2.write_line(too_long) == false);
        
        assert(writer2.close() == 4);
        assert(writer2.is_it_closed() == true);
        assert(writer2.write_line("This should not appear") == false);

        assert(write_buffer[0] == 'A');
        assert(write_buffer[1] == 'b');
        assert(write_buffer[2] == 'c');
        assert(write_buffer[3] == '\n');
        for (int i = 4; i < MAX_BUFFER_SIZE; i++) {
            assert(write_buffer[i] == '\0');
        }
    }

    return 0;
}
