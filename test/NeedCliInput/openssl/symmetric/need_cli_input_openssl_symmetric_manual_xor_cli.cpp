#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {
std::vector<uint8_t> xor_encrypt(const std::string& message,
                                 const std::vector<uint8_t>& key) {
    std::vector<uint8_t> out(message.size());
    for (size_t i = 0; i < message.size(); ++i) {
        out[i] = static_cast<uint8_t>(message[i]) ^ key[i % key.size()];
    }
    return out;
}

void run_demo() {
    const std::vector<uint8_t> key = {0x13, 0x37, 0xBE, 0xEF};

    std::string message;
    std::cout << "Enter plaintext string: ";
    std::getline(std::cin, message);
    if (message.empty()) {
        std::cout << "No input provided.\n";
        return;
    }

    auto ciphertext = xor_encrypt(message, key);
    std::cout << "XOR ciphertext (hex): ";
    for (uint8_t b : ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";

    std::string recovered(message.size(), '\0');
    for (size_t i = 0; i < message.size(); ++i) {
        recovered[i] = static_cast<char>(ciphertext[i] ^ key[i % key.size()]);
    }
    std::cout << "Recovered plaintext: " << recovered << "\n";
}
}  // namespace

int main() {
    while (true) {
        std::cout << "\n[XOR cipher demo]\n"
                     "0: Exit\n"
                     "1: Encrypt message\n"
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
            std::cout << "Error: invalid parameters detected (simulated).\n";
        } else {
            std::cout << "Invalid choice.\n";
        }
    }
    return 0;
}
