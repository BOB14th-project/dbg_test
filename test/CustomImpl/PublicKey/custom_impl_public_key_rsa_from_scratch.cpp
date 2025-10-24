#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>

namespace {

using u128 = unsigned __int128;

uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t mod) {
    return static_cast<uint64_t>((static_cast<u128>(a) * b) % mod);
}

uint64_t pow_mod(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp) {
        if (exp & 1) result = mul_mod(result, base, mod);
        base = mul_mod(base, base, mod);
        exp >>= 1;
    }
    return result;
}

bool miller_rabin(uint64_t n) {
    if (n < 2) return false;
    static const uint64_t test_primes[] = {2, 3, 5, 7, 11, 13};
    for (uint64_t p : test_primes) {
        if (n % p == 0) return n == p;
    }
    uint64_t d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++s;
    }
    auto check = [&](uint64_t a) -> bool {
        if (a % n == 0) return true;
        uint64_t x = pow_mod(a, d, n);
        if (x == 1 || x == n - 1) return true;
        for (int r = 1; r < s; ++r) {
            x = mul_mod(x, x, n);
            if (x == n - 1) return true;
        }
        return false;
    };
    for (uint64_t a : test_primes) {
        if (a >= n) break;
        if (!check(a)) return false;
    }
    return true;
}

uint64_t generate_prime(std::mt19937_64& rng, int bits) {
    std::uniform_int_distribution<uint64_t> dist(0, (uint64_t(1) << bits) - 1);
    while (true) {
        uint64_t candidate = dist(rng);
        candidate |= uint64_t(1) << (bits - 1);  // ensure high bit set
        candidate |= 1;                          // ensure odd
        if (miller_rabin(candidate)) return candidate;
    }
}

uint64_t gcd(uint64_t a, uint64_t b) {
    while (b) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

int64_t egcd(int64_t a, int64_t b, int64_t& x, int64_t& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int64_t x1 = 0, y1 = 0;
    int64_t g = egcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

uint64_t modinv(uint64_t a, uint64_t mod) {
    int64_t x = 0, y = 0;
    int64_t g = egcd(static_cast<int64_t>(a), static_cast<int64_t>(mod), x, y);
    if (g != 1) throw std::runtime_error("modular inverse does not exist");
    int64_t res = x % static_cast<int64_t>(mod);
    if (res < 0) res += static_cast<int64_t>(mod);
    return static_cast<uint64_t>(res);
}

struct RSAKeyPair {
    uint64_t n;
    uint64_t e;
    uint64_t d;
};

RSAKeyPair generate_rsa_keypair(std::mt19937_64& rng) {
    const int prime_bits = 31;  // ~62-bit modulus for didactic purposes
    uint64_t p = generate_prime(rng, prime_bits);
    uint64_t q = generate_prime(rng, prime_bits);
    while (q == p) {
        q = generate_prime(rng, prime_bits);
    }

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 65537;
    if (gcd(e, phi) != 1) {
        e = 3;
    }
    uint64_t d = modinv(e, phi);
    return {n, e, d};
}

uint64_t encode_message(const std::string& msg) {
    uint64_t value = 0;
    size_t len = std::min<size_t>(msg.size(), sizeof(uint64_t));
    std::memcpy(&value, msg.data(), len);
    return value;
}

std::string decode_message(uint64_t value) {
    std::string out(sizeof(uint64_t), '\0');
    std::memcpy(out.data(), &value, sizeof(uint64_t));
    return out;
}

}  // namespace

int main() {
    std::mt19937_64 rng(0xBADC0FFEEULL);
    RSAKeyPair key = generate_rsa_keypair(rng);

    std::string message = "RSAdemo!";
    size_t message_len = std::min<size_t>(message.size(), sizeof(uint64_t));
    uint64_t m = encode_message(message);
    if (m >= key.n) {
        std::cerr << "Message is too large for the generated modulus.\n";
        return 1;
    }

    uint64_t ciphertext = pow_mod(m, key.e, key.n);
    uint64_t recovered = pow_mod(ciphertext, key.d, key.n);

    std::cout << "RSA modulus n : " << key.n << "\n";
    std::cout << "Public exponent e: " << key.e << "\n";
    std::cout << "Private exponent d: " << key.d << "\n";
    std::cout << "Original message : " << message.substr(0, message_len) << "\n";
    std::cout << "Ciphertext       : " << ciphertext << "\n";
    std::string recovered_str(message_len, '\0');
    std::memcpy(recovered_str.data(), &recovered, message_len);
    std::cout << "Recovered bytes  : " << recovered_str << "\n";
    std::cout << "Round-trip match : " << std::boolalpha
              << (recovered == m) << "\n";
    return 0;
}
