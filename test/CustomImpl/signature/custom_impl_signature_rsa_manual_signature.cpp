#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

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
    static const uint64_t bases[] = {2, 3, 5, 7, 11};
    for (uint64_t a : bases) {
        if (n % a == 0) return n == a;
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
    for (uint64_t a : bases) {
        if (a >= n) break;
        if (!check(a)) return false;
    }
    return true;
}

uint64_t generate_prime(std::mt19937_64& rng, int bits) {
    std::uniform_int_distribution<uint64_t> dist(0, (uint64_t(1) << bits) - 1);
    while (true) {
        uint64_t candidate = dist(rng);
        candidate |= uint64_t(1) << (bits - 1);
        candidate |= 1;
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

constexpr std::array<uint32_t, 64> SHA256_K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr std::array<uint32_t, 8> SHA256_INIT = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

std::array<uint8_t, 32> sha256(const std::string& message) {
    std::vector<uint8_t> data(message.begin(), message.end());
    uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8;
    data.push_back(0x80);
    while ((data.size() % 64) != 56) {
        data.push_back(0x00);
    }
    for (int i = 7; i >= 0; --i) {
        data.push_back(static_cast<uint8_t>((bit_len >> (8 * i)) & 0xFF));
    }

    std::array<uint32_t, 8> state = SHA256_INIT;
    std::array<uint32_t, 64> w{};

    for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
        for (int i = 0; i < 16; ++i) {
            size_t offset = chunk + i * 4;
            w[i] = (static_cast<uint32_t>(data[offset]) << 24) |
                   (static_cast<uint32_t>(data[offset + 1]) << 16) |
                   (static_cast<uint32_t>(data[offset + 2]) << 8) |
                   static_cast<uint32_t>(data[offset + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                          (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                          (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    std::array<uint8_t, 32> digest{};
    for (int i = 0; i < 8; ++i) {
        digest[i * 4 + 0] = static_cast<uint8_t>((state[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xFF);
    }
    return digest;
}

struct RSAKeyPair {
    uint64_t n;
    uint64_t e;
    uint64_t d;
};

RSAKeyPair generate_rsa_keypair(std::mt19937_64& rng) {
    const int prime_bits = 31;
    uint64_t p = generate_prime(rng, prime_bits);
    uint64_t q = generate_prime(rng, prime_bits);
    while (q == p) q = generate_prime(rng, prime_bits);

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 65537;
    if (gcd(e, phi) != 1) e = 3;
    uint64_t d = modinv(e, phi);
    return {n, e, d};
}

uint64_t reduce_digest(const std::array<uint8_t, 32>& digest, uint64_t mod) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | digest[i];
    }
    return value % mod;
}

}  // namespace

int main() {
    std::mt19937_64 rng(0x53494E47ULL);
    RSAKeyPair key = generate_rsa_keypair(rng);

    const std::string message = "classical-signature-demo";
    auto digest = sha256(message);
    uint64_t hash_int = reduce_digest(digest, key.n);

    uint64_t signature = pow_mod(hash_int, key.d, key.n);
    uint64_t recovered = pow_mod(signature, key.e, key.n);

    std::cout << "RSA modulus n : " << key.n << "\n";
    std::cout << "Public exponent e: " << key.e << "\n";
    std::cout << "Private exponent d: " << key.d << "\n";
    std::cout << "Message          : " << message << "\n";
    std::cout << "SHA-256 (msb 64) : 0x" << std::hex << hash_int << std::dec << "\n";
    std::cout << "Signature        : " << signature << "\n";
    std::cout << "Verify result    : " << (recovered == hash_int ? "OK" : "FAIL")
              << "\n";

    const std::string tampered = "classical-signature-demo!";
    auto tampered_digest = sha256(tampered);
    uint64_t tampered_hash = reduce_digest(tampered_digest, key.n);
    uint64_t tampered_verify = pow_mod(signature, key.e, key.n);
    std::cout << "Tampered verify  : "
              << (tampered_verify == tampered_hash ? "OK" : "FAIL") << "\n";
    return 0;
}
