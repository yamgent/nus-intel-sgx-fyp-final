#include "helper_common_meter.h"
#include <assert.h>

int main() {
    assert(hcmtr_is_label("\tmov a, b") == false);
    assert(hcmtr_is_label(" \ttest:  \t ") == true);

    assert(hcmtr_is_instruction(" \ttest:  \t ") == false);
    assert(hcmtr_is_instruction("\t.abc") == false);
    assert(hcmtr_is_instruction("\tmov a, b ") == true);
}
