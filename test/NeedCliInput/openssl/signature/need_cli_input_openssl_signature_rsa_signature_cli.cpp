#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>

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

uint64_t egcd(uint64_t a, uint64_t b, int64_t& x, int64_t& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int64_t x1 = 0, y1 = 0;
    uint64_t g = egcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - static_cast<int64_t>(a / b) * y1;
    return g;
}

uint64_t modinv(uint64_t a, uint64_t mod) {
    int64_t x = 0, y = 0;
    uint64_t g = egcd(a, mod, x, y);
    if (g != 1) {
        throw std::runtime_error("inverse does not exist");
    }
    int64_t res = x % static_cast<int64_t>(mod);
    if (res < 0) res += mod;
    return static_cast<uint64_t>(res);
}

uint64_t toy_hash(const std::string& message, uint64_t mod) {
    uint64_t h = 0;
    for (unsigned char c : message) {
        h = (h * 131 + c) % mod;
    }
    return h;
}

void run_demo() {
    const uint64_t p = 29573;
    const uint64_t q = 29611;
    const uint64_t n = p * q;
    const uint64_t phi = (p - 1) * (q - 1);
    const uint64_t e = 3;  // intentionally small public exponent
    const uint64_t d = modinv(e, phi);

    std::string message;
    std::cout << "Enter message to sign: ";
    std::getline(std::cin, message);
    if (message.empty()) {
        std::cout << "Message is empty.\n";
        return;
    }

    uint64_t digest = toy_hash(message, n);
    uint64_t signature = modexp(digest, d, n);
    uint64_t verify = modexp(signature, e, n);

    std::cout << "toy hash: " << digest << "\n";
    std::cout << "signature: " << signature << "\n";
    std::cout << "Verification result: " << (verify == digest ? "OK" : "FAIL")
              << "\n";
}
}  // namespace

int main() {
    while (true) {
        std::cout << "\n[RSA signature demo]\n"
                     "0: Exit\n"
                     "1: Sign/verify\n"
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
            std::cout << "Error: signature creation failed (simulated).\n";
        } else {
            std::cout << "Invalid choice.\n";
        }
    }
    return 0;
}
