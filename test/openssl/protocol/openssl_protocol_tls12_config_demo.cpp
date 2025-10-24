#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cstdio>

int main() {
    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::fprintf(stderr, "SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!RC4:!MD5:!PSK") != 1) {
        std::fprintf(stderr, "Failed to set cipher list\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    std::printf("OpenSSL configured for TLS 1.0 - TLS 1.2 with classic cipher suites.\n");
    SSL_CTX_free(ctx);
    return 0;
}
