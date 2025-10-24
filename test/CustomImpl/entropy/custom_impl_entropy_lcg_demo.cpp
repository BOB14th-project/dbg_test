#include <cstdint>
#include <iomanip>
#include <iostream>

class LCG {
   public:
    LCG(uint32_t seed, uint32_t a = 1664525, uint32_t c = 1013904223,
        uint32_t m = 0xFFFFFFFFu)
        : state_(seed), a_(a), c_(c), m_(m) {}

    uint32_t next() {
        state_ = (static_cast<uint64_t>(a_) * state_ + c_) & m_;
        return state_;
    }

    void fill(uint8_t* out, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            if (i % 4 == 0) {
                buffer_ = next();
            }
            out[i] = static_cast<uint8_t>((buffer_ >> ((i % 4) * 8)) & 0xFF);
        }
    }

   private:
    uint32_t state_;
    uint32_t a_;
    uint32_t c_;
    uint32_t m_;
    uint32_t buffer_ = 0;
};

int main() {
    LCG rng(0x12345678);
    uint8_t sample[16];
    rng.fill(sample, sizeof(sample));

    std::cout << "LCG output: ";
    for (uint8_t b : sample) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";

    // 동일 매개변수 사용 시 출력이 완전히 결정적임을 보여줌
    LCG rng2(0x12345678);
    uint8_t sample2[16];
    rng2.fill(sample2, sizeof(sample2));

    bool identical = true;
    for (size_t i = 0; i < sizeof(sample); ++i) {
        if (sample[i] != sample2[i]) {
            identical = false;
            break;
        }
    }
    std::cout << "Re-seeded output matches: " << (identical ? "YES" : "NO")
              << "\n";
    return 0;
}
