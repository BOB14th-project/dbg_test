#include <openssl/rand.h>

#include <cstdio>

int main() {
    unsigned char buf[32];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        std::fprintf(stderr, "RAND_bytes failed\n");
        return 1;
    }

    std::printf("OpenSSL RAND_bytes sample:\n");
    for (size_t i = 0; i < sizeof(buf); ++i) {
        std::printf("%02x", buf[i]);
    }
    std::printf("\n");
    return 0;
}
