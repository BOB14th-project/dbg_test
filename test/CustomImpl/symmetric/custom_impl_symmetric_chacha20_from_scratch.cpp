#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

using State = std::array<uint32_t, 16>;

constexpr uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b;
    d ^= a;
    d = rotl32(d, 16);

    c += d;
    b ^= c;
    b = rotl32(b, 12);

    a += b;
    d ^= a;
    d = rotl32(d, 8);

    c += d;
    b ^= c;
    b = rotl32(b, 7);
}

State chacha20_block(const std::array<uint8_t, 32>& key,
                     uint32_t counter,
                     const std::array<uint8_t, 12>& nonce) {
    const uint32_t constants[4] = {
        0x61707865,  // "expa"
        0x3320646e,  // "nd 3"
        0x79622d32,  // "2-by"
        0x6b206574   // "te k"
    };

    State state{};
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];

    for (int i = 0; i < 8; ++i) {
        state[4 + i] = static_cast<uint32_t>(key[i * 4]) |
                       (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                       (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                       (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
    }

    state[12] = counter;
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = static_cast<uint32_t>(nonce[i * 4]) |
                        (static_cast<uint32_t>(nonce[i * 4 + 1]) << 8) |
                        (static_cast<uint32_t>(nonce[i * 4 + 2]) << 16) |
                        (static_cast<uint32_t>(nonce[i * 4 + 3]) << 24);
    }

    State working = state;
    for (int i = 0; i < 10; ++i) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);
        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        working[i] += state[i];
    }
    return working;
}

std::vector<uint8_t> chacha20_stream(const std::array<uint8_t, 32>& key,
                                     uint32_t counter,
                                     const std::array<uint8_t, 12>& nonce,
                                     size_t length) {
    std::vector<uint8_t> stream;
    stream.reserve(length);
    size_t generated = 0;
    uint32_t ctr = counter;
    while (generated < length) {
        State block = chacha20_block(key, ctr++, nonce);
        for (uint32_t word : block) {
            for (int i = 0; i < 4 && generated < length; ++i) {
                stream.push_back(static_cast<uint8_t>((word >> (8 * i)) & 0xFF));
                ++generated;
            }
        }
    }
    return stream;
}

std::vector<uint8_t> chacha20_xor(const std::vector<uint8_t>& plaintext,
                                  const std::array<uint8_t, 32>& key,
                                  uint32_t counter,
                                  const std::array<uint8_t, 12>& nonce) {
    auto keystream = chacha20_stream(key, counter, nonce, plaintext.size());
    std::vector<uint8_t> output(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); ++i) {
        output[i] = plaintext[i] ^ keystream[i];
    }
    return output;
}

void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " ";
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

}  // namespace

int main() {
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i);
    }

    std::array<uint8_t, 12> nonce{};
    nonce[4] = 0x4a;

    const uint32_t counter = 1;
    const std::string message = "ChaCha20 implemented from scratch.";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    auto ciphertext = chacha20_xor(plaintext, key, counter, nonce);
    auto recovered = chacha20_xor(ciphertext, key, counter, nonce);

    print_hex("Ciphertext:", ciphertext);
    std::cout << "Recovered : " << std::string(recovered.begin(), recovered.end())
              << "\n";
    return 0;
}
