CXX = g++
CXXFLAGS = -std=c++17 -g -O0 -Wall

# Build directory
BUILD_DIR = build

# Target programs
DEBUGGER = $(BUILD_DIR)/aes_sbox_debugger
DEBUGGER_V2 = $(BUILD_DIR)/aes_sbox_debugger_v2
DEBUGGER_V3 = $(BUILD_DIR)/aes_sbox_debugger_v3
AES_TEST = $(BUILD_DIR)/aes256_test
OPENSSL_TEST = $(BUILD_DIR)/openssl_aes_test

# OpenSSL flags
OPENSSL_FLAGS = -lssl -lcrypto

.PHONY: all clean test test-v1 test-v2 test-v3 test-openssl help

all: $(DEBUGGER_V3) $(AES_TEST)

# Build the debugger v1
$(DEBUGGER): aes_sbox_debugger.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "[+] Built debugger v1: $(DEBUGGER)"

# Build the debugger v2
$(DEBUGGER_V2): aes_sbox_debugger_v2.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "[+] Built debugger v2: $(DEBUGGER_V2)"

# Build the debugger v3 (Hardware Watchpoint)
$(DEBUGGER_V3): aes_sbox_debugger_v3.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "[+] Built debugger v3: $(DEBUGGER_V3)"

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

# Run the debugger v3 on custom AES implementation (recommended - with hardware watchpoint)
test: $(DEBUGGER_V3) $(AES_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger v3 (Hardware Watchpoint) ==="
	@echo ""
	$(DEBUGGER_V3) $(AES_TEST)

# Run the debugger v1 on custom AES implementation
test-v1: $(DEBUGGER) $(AES_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger v1 ==="
	@echo ""
	$(DEBUGGER) $(AES_TEST)

# Run the debugger v2 on custom AES implementation
test-v2: $(DEBUGGER_V2) $(AES_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger v2 ==="
	@echo ""
	$(DEBUGGER_V2) $(AES_TEST)

# Run the debugger v3 on custom AES implementation
test-v3: $(DEBUGGER_V3) $(AES_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger v3 ==="
	@echo ""
	$(DEBUGGER_V3) $(AES_TEST)

# Run debugger v3 with verbose mode
test-verbose: $(DEBUGGER_V3) $(AES_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger v3 (Verbose) ==="
	@echo ""
	$(DEBUGGER_V3) -v $(AES_TEST)

# Run debugger on OpenSSL implementation (if available)
test-openssl: $(DEBUGGER_V3) $(OPENSSL_TEST)
	@echo ""
	@echo "=== Running AES S-box Debugger on OpenSSL ==="
	@echo ""
	$(DEBUGGER_V3) $(OPENSSL_TEST)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "[+] Cleaned build directory"

# Show help
help:
	@echo "AES S-box Debugger - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build debugger v3 and AES test programs (default)"
	@echo "  test           - Run debugger v3 with hardware watchpoint (recommended)"
	@echo "  test-v1        - Run debugger v1 (single-step mode)"
	@echo "  test-v2        - Run debugger v2 (memory scan only)"
	@echo "  test-v3        - Run debugger v3 (hardware watchpoint)"
	@echo "  test-verbose   - Run debugger v3 with verbose output"
	@echo "  test-openssl   - Run debugger v3 on OpenSSL AES implementation"
	@echo "  clean          - Remove build directory"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Build directory: $(BUILD_DIR)/"
	@echo ""
	@echo "Example usage:"
	@echo "  make                # Build everything"
	@echo "  make test           # Run v3 debugger (hardware watchpoint)"
	@echo "  make test-verbose   # Run v3 with detailed output"
	@echo "  make clean          # Clean build artifacts"
