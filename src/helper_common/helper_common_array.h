#ifndef HELPER_COMMON_ARRAY_H
#define HELPER_COMMON_ARRAY_H

#include <stdint.h>

class hca_CharArray {
public:
    uint8_t* array;

private:
    uint32_t size;

public:
    hca_CharArray(uint32_t size);
    ~hca_CharArray();

    uint32_t get_size();
};

#endif
