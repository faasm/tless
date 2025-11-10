#include "attestation/attestation.h"
#include "jwt.h"

#include <iostream>

int main() {
    std::cout << "att-client-sgx: running test..." << std::endl;

    try {
        const std::string jwt =
            accless::attestation::getMockSgxAttestationJwt();
        if (jwt.empty()) {
            std::cerr << "att-client-sgx: empty JWT returned" << std::endl;
            return 1;
        }

        std::cout << "att-client-sgx: received JWT" << std::endl;
        if (!accless::jwt::verify(jwt)) {
            std::cerr << "att-client-sgx: JWT signature verification failed"
                      << std::endl;
            return 1;
        }

        std::cout << "att-client-sgx: JWT signature verified" << std::endl;

        // TODO: get the partial keys out, and use them to decrypt something.

        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "att-client-sgx: error: " << ex.what() << std::endl;
    } catch (...) {
        std::cerr << "att-client-sgx: unexpected error" << std::endl;
    }

    return 1;
}
