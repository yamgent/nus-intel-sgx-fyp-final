#include <iostream>
#include <cassert>
#include <cstdlib>

void do_work(int input);

int main(int argc, char** argv) {
    register int instructions_counter asm ("r15");
    instructions_counter = 0;

    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <input>" << std::endl;
        return 1;
    }

    do_work(atoi(argv[1]));

    int instructions_counter_copy = instructions_counter;
    std::cout << "Total instructions made: " <<
        instructions_counter_copy << std::endl;

    return 0;
}
