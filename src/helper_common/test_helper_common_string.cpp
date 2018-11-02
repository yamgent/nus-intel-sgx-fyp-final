#include "helper_common_string.h"
#include <assert.h>

int main() {
    assert(hcstr_trim("    abc def ghi\t   ") == "abc def ghi");
    assert(hcstr_trim("a") == "a");
    assert(hcstr_trim("") == "");
    assert(hcstr_trim(" ") == "");
    assert(hcstr_trim("        ") == "");

    assert(hcstr_starts_with("abcdef", "abc") == true);
    assert(hcstr_starts_with("abcdef", "def") == false);
    assert(hcstr_starts_with("abcdef", "abcdefghi") == false);

    assert(hcstr_ends_with("abcdef", "def") == true);
    assert(hcstr_ends_with("abcdef", "abc") == false);
    assert(hcstr_ends_with("abcdef", "xyzabcdef") == false);
}
