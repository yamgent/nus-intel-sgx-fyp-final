#include "helper_common_string.h"

// ' ' and '\t' are whitespaces
bool hcstr_is_whitespace_char(char character) {
    return character == ' ' ||
        character == '\t';
}

// remove trailing whitespace from front and back
std::string hcstr_trim(const std::string original) {
    if (original.size() == 0) {
        return "";
    }

    if (original.size() == 1) {
        if (hcstr_is_whitespace_char(original[0])) {
            return "";
        } else {
            return original;
        }
    }

    uint32_t first_non_whitespace = 0;
    while (first_non_whitespace < original.size() - 1 &&
            hcstr_is_whitespace_char(original[first_non_whitespace])) {
        first_non_whitespace++;    
    }

    uint32_t last_non_whitespace = original.size() - 1;
    while (last_non_whitespace > 0 &&
            hcstr_is_whitespace_char(original[last_non_whitespace])) {
        last_non_whitespace--;
    }

    if (first_non_whitespace > last_non_whitespace) {
        return "";
    }

    return original.substr(first_non_whitespace, last_non_whitespace - first_non_whitespace + 1);
}

// whether `str` starts with `prefix`
bool hcstr_starts_with(const std::string str, const std::string prefix) {
    if (prefix.length() > str.length()) {
        return false;
    }

    return str.substr(0, prefix.length()) == prefix;
}

// whether `str` ends with `suffix`
bool hcstr_ends_with(const std::string str, const std::string suffix) {
    if (suffix.length() > str.length()) {
        return false;
    }

    return str.substr(str.length() - suffix.length()) == suffix;
}
