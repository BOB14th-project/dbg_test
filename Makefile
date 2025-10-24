CXX = g++
CXXFLAGS = -std=c++17 -g -O0 -Wall

# Build directory
BUILD_DIR = build

# Target programs
DEBUGGER = $(BUILD_DIR)/aes_sbox_debugger
DEBUGGER_V2 = $(BUILD_DIR)/aes_sbox_debugger_v2
AES_TEST = $(BUILD_DIR)/aes256_test
OPENSSL_TEST = $(BUILD_DIR)/openssl_aes_test

# OpenSSL flags
OPENSSL_FLAGS = -lssl -lcrypto

.PHONY: all clean test test-v1 test-openssl help

all: $(DEBUGGER_V2) $(AES_TEST)

# Build the debugger v1
$(DEBUGGER): aes_sbox_debugger.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "[+] Built debugger v1: $(DEBUGGER)"

# Build the debugger v2
$(DEBUGGER_V2): aes_sbox_debugger_v2.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "[+] Built debugger v2: $(DEBUGGER_V2)"

# Build the custom AES implementation test
$(AES_TEST): test/CustomImpl/symmetric/custom_impl_symmetric_aes256_ecb_from_scratch.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "[+] Built AES test: $(AES_TEST)"

# Build OpenSSL AES test (optional)
$(OPENSSL_TEST): test/openssl/symmetric/openssl_symmetric_aes_lib_test.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $< $(OPENSSL_FLAGS)
	@echo "[+] Built OpenSSL AES test: $(OPENSSL_TEST)"

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@echo "[+] Created build directory: $(BUILD_DIR)"

# Run the debugger v2 on custom AES implementation (recommended)
test: $(DEBUGGER_V2) $(AES_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger v2 ==="
	@echo ""
	$(DEBUGGER_V2) $(AES_TEST)

# Run the debugger v1 on custom AES implementation
test-v1: $(DEBUGGER) $(AES_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger v1 ==="
	@echo ""
	$(DEBUGGER) $(AES_TEST)

# Run debugger on OpenSSL implementation (if available)
test-openssl: $(DEBUGGER_V2) $(OPENSSL_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger on OpenSSL ==="
	@echo ""
	$(DEBUGGER_V2) $(OPENSSL_TEST)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "[+] Cleaned build directory"

# Show help
help:
	@echo "AES S-box Debugger - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build debugger v2 and AES test programs"
	@echo "  test          - Run debugger v2 on custom AES implementation (recommended)"
	@echo "  test-v1       - Run debugger v1 on custom AES implementation"
	@echo "  test-openssl  - Run debugger v2 on OpenSSL AES implementation"
	@echo "  clean         - Remove build directory"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Build directory: $(BUILD_DIR)/"
	@echo ""
	@echo "Example usage:"
	@echo "  make          # Build everything"
	@echo "  make test     # Run the debugger v2"
	@echo "  make clean    # Clean build artifacts"
