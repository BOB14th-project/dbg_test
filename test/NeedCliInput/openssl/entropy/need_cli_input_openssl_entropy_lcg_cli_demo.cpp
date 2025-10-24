#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>

namespace {
class LCG {
   public:
    explicit LCG(uint32_t seed,
                 uint32_t a = 1664525,
                 uint32_t c = 1013904223,
                 uint32_t m = 0xFFFFFFFFu)
        : state_(seed), a_(a), c_(c), m_(m) {}

    uint32_t next() {
        state_ = (static_cast<uint64_t>(a_) * state_ + c_) & m_;
        return state_;
    }

   private:
    uint32_t state_;
    uint32_t a_;
    uint32_t c_;
    uint32_t m_;
};

void run_demo() {
    uint32_t seed = 0;
    std::cout << "Enter seed (integer): ";
    if (!(std::cin >> seed)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Input was not an integer.\n";
        return;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    LCG rng(seed);
    std::cout << "LCG output (10 values): ";
    for (int i = 0; i < 10; ++i) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << rng.next();
        if (i != 9) std::cout << " ";
    }
    std::cout << std::dec << "\n";
}
}  // namespace

int main() {
    while (true) {
        std::cout << "\n[LCG entropy demo]\n"
                     "0: Exit\n"
                     "1: Generate random values\n"
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
            std::cout << "Error: RNG initialization failed (simulated).\n";
        } else {
            std::cout << "Invalid choice.\n";
        }
    }
    return 0;
}
