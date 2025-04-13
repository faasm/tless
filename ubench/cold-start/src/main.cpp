#include "tless.h"

#include <cstdint>
#include <iostream>
#include <string>

int main()
{
    if (tless::checkChain("word-count", "splitter", 1)) {
        std::cout << "accless: access approved :-)" << std::endl;
    } else {
        std::cout << "accless: access denied :-(" << std::endl;
    }

    return 0;
}
