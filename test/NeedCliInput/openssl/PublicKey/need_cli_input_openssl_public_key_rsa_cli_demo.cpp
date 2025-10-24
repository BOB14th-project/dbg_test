#include <cstdint>
#include <iostream>
#include <limits>

namespace {
struct RSAKey {
    uint64_t n;
    uint64_t exponent;
};

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
        throw std::runtime_error("modular inverse does not exist");
    }
    int64_t res = x % static_cast<int64_t>(mod);
    if (res < 0) res += mod;
    return static_cast<uint64_t>(res);
}

void generate_rsa(RSAKey& pub, RSAKey& priv) {
    const uint64_t p = 31337;
    const uint64_t q = 31357;
    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 65537;
    uint64_t d = modinv(e, phi);
    pub = {n, e};
    priv = {n, d};
}

void run_demo() {
    RSAKey pub{}, priv{};
    generate_rsa(pub, priv);

    std::cout << "RSA public key n=" << pub.n << ", e=" << pub.exponent << "\n";
    std::cout << "Enter an integer between 0 and " << pub.n - 1 << ": ";
    uint64_t message = 0;
    if (!(std::cin >> message)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Input was not an integer.\n";
        return;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if (message >= pub.n) {
        std::cout << "Message outside modulus range.\n";
        return;
    }

    uint64_t ciphertext = modexp(message, pub.exponent, pub.n);
    uint64_t recovered = modexp(ciphertext, priv.exponent, priv.n);

    std::cout << "Ciphertext: " << ciphertext << "\n";
    std::cout << "Recovered: " << recovered << "\n";
}
}  // namespace

int main() {
    while (true) {
        std::cout << "\n[RSA demo]\n"
                     "0: Exit\n"
                     "1: RSA encrypt/decrypt\n"
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
            std::cout << "Error: RSA key generation failed (simulated).\n";
        } else {
            std::cout << "Invalid choice.\n";
        }
    }
    return 0;
}
