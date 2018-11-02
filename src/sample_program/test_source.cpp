register int instruction_counter asm("r15");
#include <iostream>

void do_work(int input) {
    while (input-- > 0) {
        std::cout << "Hello World!" << std::endl;
    }
}

