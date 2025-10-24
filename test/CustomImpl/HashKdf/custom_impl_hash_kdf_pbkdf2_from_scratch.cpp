#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

namespace {

using ByteVec = std::vector<uint8_t>;

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

std::array<uint8_t, 32> sha256(const ByteVec& data) {
    ByteVec padded = data;
    uint64_t bit_len = static_cast<uint64_t>(padded.size()) * 8;
    padded.push_back(0x80);
    while ((padded.size() % 64) != 56) {
        padded.push_back(0x00);
    }
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>((bit_len >> (8 * i)) & 0xFF));
    }

    std::array<uint32_t, 8> state = SHA256_INIT;
    std::array<uint32_t, 64> w{};

    for (size_t chunk = 0; chunk < padded.size(); chunk += 64) {
        for (int i = 0; i < 16; ++i) {
            size_t offset = chunk + i * 4;
            w[i] = (static_cast<uint32_t>(padded[offset]) << 24) |
                   (static_cast<uint32_t>(padded[offset + 1]) << 16) |
                   (static_cast<uint32_t>(padded[offset + 2]) << 8) |
                   static_cast<uint32_t>(padded[offset + 3]);
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

std::array<uint8_t, 32> hmac_sha256(const ByteVec& key, const ByteVec& message) {
    constexpr size_t block_size = 64;
    ByteVec key_block = key;
    if (key_block.size() > block_size) {
        auto hashed = sha256(key_block);
        key_block.assign(hashed.begin(), hashed.end());
    }
    key_block.resize(block_size, 0x00);

    ByteVec o_key_pad(block_size), i_key_pad(block_size);
    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    ByteVec inner(i_key_pad);
    inner.insert(inner.end(), message.begin(), message.end());
    auto inner_hash = sha256(inner);

    ByteVec outer(o_key_pad);
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return sha256(outer);
}

ByteVec pbkdf2_sha256(const ByteVec& password,
                      const ByteVec& salt,
                      uint32_t iterations,
                      size_t dk_len) {
    if (iterations == 0) {
        throw std::runtime_error("iterations must be positive");
    }
    ByteVec derived;
    uint32_t block_index = 1;
    while (derived.size() < dk_len) {
        ByteVec salt_block(salt);
        salt_block.push_back(static_cast<uint8_t>((block_index >> 24) & 0xFF));
        salt_block.push_back(static_cast<uint8_t>((block_index >> 16) & 0xFF));
        salt_block.push_back(static_cast<uint8_t>((block_index >> 8) & 0xFF));
        salt_block.push_back(static_cast<uint8_t>(block_index & 0xFF));

        auto u = hmac_sha256(password, salt_block);
        std::array<uint8_t, 32> t = u;
        for (uint32_t i = 1; i < iterations; ++i) {
            ByteVec u_input(u.begin(), u.end());
            u = hmac_sha256(password, u_input);
            for (size_t j = 0; j < t.size(); ++j) {
                t[j] ^= u[j];
            }
        }

        size_t take = std::min<size_t>(t.size(), dk_len - derived.size());
        derived.insert(derived.end(), t.begin(), t.begin() + take);
        ++block_index;
    }
    return derived;
}

void print_hex(const ByteVec& data) {
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

}  // namespace

int main() {
    const std::string password_str = "classical-password";
    const std::string salt_str = "salt";
    ByteVec password(password_str.begin(), password_str.end());
    ByteVec salt(salt_str.begin(), salt_str.end());

    ByteVec derived = pbkdf2_sha256(password, salt, 10000, 32);
    std::cout << "PBKDF2-HMAC-SHA256 output:\n";
    print_hex(derived);
    return 0;
}
