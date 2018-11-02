#include "helper_common_meter.h"
#include "helper_common_string.h"

// a label ends with a ':'
bool hcmtr_is_label(std::string line) {
    std::string trimmed_line = hcstr_trim(line);

    return hcstr_ends_with(trimmed_line, ":");
}

// an instruction is NOT a label and does not start with a '.'
bool hcmtr_is_instruction(std::string line) {
    if (hcmtr_is_label(line)) {
        return false;
    }

    std::string trimmed_line = hcstr_trim(line);

    if (trimmed_line.empty()) {
        return false;
    }

    return !hcstr_starts_with(trimmed_line, ".");
}

// does the instruction contains the usage of register 15
bool hcmtr_instruction_uses_r15(std::string line) {
    return line.find("%r15") != std::string::npos;
}
