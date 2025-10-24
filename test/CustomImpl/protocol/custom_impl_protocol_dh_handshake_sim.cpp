#include <cstdint>
#include <iostream>

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

int main() {
    const uint64_t p = 467;  // 작은 소수
    const uint64_t g = 2;
    const uint64_t alice_secret = 153;
    const uint64_t bob_secret = 97;

    uint64_t alice_public = modexp(g, alice_secret, p);
    uint64_t bob_public = modexp(g, bob_secret, p);
    uint64_t shared_alice = modexp(bob_public, alice_secret, p);
    uint64_t shared_bob = modexp(alice_public, bob_secret, p);

    std::cout << "Alice public: " << alice_public << "\n";
    std::cout << "Bob public: " << bob_public << "\n";
    std::cout << "Shared secret (Alice): " << shared_alice << "\n";
    std::cout << "Shared secret (Bob): " << shared_bob << "\n";

    // MITM 공격: 중간자가 공개키를 g^0 = 1로 바꿔치기
    uint64_t forged_secret = modexp(1, alice_secret, p);
    std::cout << "MITM forged secret: " << forged_secret << "\n";
    return 0;
}
