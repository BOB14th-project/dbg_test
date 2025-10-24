#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstdio>
#include <cstring>

int main() {
    const char* password = "classical-password";
    const unsigned char salt[] = "salt";
    unsigned char out[32];

    if (PKCS5_PBKDF2_HMAC(password, std::strlen(password),
                          salt, sizeof(salt) - 1,
                          10000, EVP_sha256(),
                          sizeof(out), out) != 1) {
        std::fprintf(stderr, "PBKDF2 failed\n");
        return 1;
    }

    std::printf("PKCS5_PBKDF2_HMAC output:\n");
    for (size_t i = 0; i < sizeof(out); ++i) {
        std::printf("%02x", out[i]);
    }
    std::printf("\n");
    return 0;
}
