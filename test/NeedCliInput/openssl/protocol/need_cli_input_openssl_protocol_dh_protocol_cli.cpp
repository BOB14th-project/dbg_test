#include <cstdint>
#include <iostream>
#include <limits>

namespace {
uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

void run_demo() {
    const uint64_t p = 467;
    const uint64_t g = 2;
    uint64_t alice_secret = 0;
    uint64_t bob_secret = 0;

    std::cout << "Enter Alice's secret exponent (e.g., 153): ";
    if (!(std::cin >> alice_secret)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Input was not an integer.\n";
        return;
    }
    std::cout << "Enter Bob's secret exponent (e.g., 97): ";
    if (!(std::cin >> bob_secret)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Input was not an integer.\n";
        return;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    uint64_t alice_public = modexp(g, alice_secret, p);
    uint64_t bob_public = modexp(g, bob_secret, p);
    uint64_t alice_shared = modexp(bob_public, alice_secret, p);
    uint64_t bob_shared = modexp(alice_public, bob_secret, p);

    std::cout << "Alice public value: " << alice_public << "\n";
    std::cout << "Bob public value: " << bob_public << "\n";
    std::cout << "Alice shared secret: " << alice_shared << "\n";
    std::cout << "Bob shared secret: " << bob_shared << "\n";

    if (alice_shared != bob_shared) {
        std::cout << "Warning: shared secrets do not match!\n";
    }

    uint64_t forged = modexp(1, alice_secret, p);
    std::cout << "MITM forcing public key to 1 yields shared secret: " << forged
              << "\n";
}
}  // namespace

int main() {
    while (true) {
        std::cout << "\n[DH protocol demo]\n"
                     "0: Exit\n"
                     "1: Run key exchange\n"
                     "2: Simulate error\n"
                     "Choice: ";
        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Please enter a number.\n";
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == 0) {
            std::cout << "Exiting program.\n";
            break;
        } else if (choice == 1) {
            run_demo();
        } else if (choice == 2) {
            std::cout << "Error: protocol negotiation failed (simulated).\n";
        } else {
            std::cout << "Invalid choice.\n";
        }
    }
    return 0;
}
