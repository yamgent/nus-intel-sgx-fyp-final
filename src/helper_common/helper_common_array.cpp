#include "helper_common_array.h"
#include <stdint.h>

hca_CharArray::hca_CharArray(uint32_t size) {
    this->size = size;
    this->array = new uint8_t[size];
}

hca_CharArray::~hca_CharArray() {
    delete[] array;
}

uint32_t hca_CharArray::get_size() {
    return size;
}
