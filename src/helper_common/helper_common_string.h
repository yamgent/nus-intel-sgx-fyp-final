#ifndef HELPER_COMMON_STRING_H
#define HELPER_COMMON_STRING_H

#include <string>

bool hcstr_is_whitespace_char(char character);

std::string hcstr_trim(const std::string original);
bool hcstr_starts_with(const std::string str, const std::string prefix);
bool hcstr_ends_with(const std::string str, const std::string suffix);

#endif
