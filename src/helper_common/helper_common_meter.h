#ifndef HELPER_COMMON_METER_H
#define HELPER_COMMON_METER_H

#include <string>

bool hcmtr_is_label(std::string line);
bool hcmtr_is_instruction(std::string line);
bool hcmtr_instruction_uses_r15(std::string line);

#endif
