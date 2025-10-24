#include <iostream>
#include <cstdint>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <errno.h>
#include <signal.h>

// AES S-box 테이블 (감지 대상)
const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

class AESSboxDebugger {
private:
    pid_t child_pid;
    std::string target_program;
    std::vector<unsigned long> sbox_addresses;
    int sbox_access_count = 0;
    bool verbose = false;

public:
    AESSboxDebugger(const std::string& program, bool v = false)
        : child_pid(-1), target_program(program), verbose(v) {}

    // 타겟 프로그램의 메모리 맵에서 SBOX 주소 찾기
    bool find_sbox_in_memory() {
        std::string maps_path = "/proc/" + std::to_string(child_pid) + "/maps";
        std::ifstream maps_file(maps_path);

        if (!maps_file.is_open()) {
            std::cerr << "Failed to open " << maps_path << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(maps_file, line)) {
            // 실행 가능한 영역과 읽기 전용 데이터 영역 검색
            if (line.find("r-xp") != std::string::npos ||
                line.find("r--p") != std::string::npos) {

                unsigned long start, end;
                char perms[5];
                sscanf(line.c_str(), "%lx-%lx %s", &start, &end, perms);

                // 메모리 영역 읽기 (8바이트 정렬로 스캔)
                for (unsigned long addr = start; addr < end - 256; addr += 8) {
                    uint8_t buffer[256];
                    bool read_success = true;

                    // ptrace로 메모리 읽기
                    for (int i = 0; i < 256; i += sizeof(long)) {
                        errno = 0;
                        long data = ptrace(PTRACE_PEEKDATA, child_pid, addr + i, NULL);
                        if (errno != 0) {
                            read_success = false;
                            break;
                        }
                        memcpy(&buffer[i], &data, sizeof(long));
                    }

                    if (!read_success) continue;

                    // SBOX 패턴 매칭
                    if (memcmp(buffer, SBOX, 256) == 0) {
                        sbox_addresses.push_back(addr);
                        std::cout << "[+] Found SBOX at address: 0x"
                                  << std::hex << addr << std::dec << std::endl;
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // 실제 S-box 접근 시 호출되는 함수 (간단 버전)
    void on_sbox_access(unsigned long rip, uint8_t input, uint8_t output) {
        sbox_access_count++;

        std::cout << "[" << std::setw(4) << sbox_access_count << "] S-box access at RIP: 0x"
                  << std::hex << rip << std::dec;
        std::cout << " | Input: 0x" << std::hex << std::setw(2) << std::setfill('0')
                  << (int)input;
        std::cout << " -> Output: 0x" << std::setw(2) << std::setfill('0')
                  << (int)output << std::dec << std::endl;
    }

    // 명령어 트레이싱 (브레이크포인트 방식)
    void trace_with_breakpoints() {
        int status;
        struct user_regs_struct regs;

        std::cout << "[*] Starting execution with function tracing..." << std::endl;

        // sub_bytes 함수에 브레이크포인트를 걸기 위해서는 심볼 정보가 필요
        // 여기서는 간단히 실행하고 모니터링

        ptrace(PTRACE_CONT, child_pid, 0, 0);

        while (waitpid(child_pid, &status, 0)) {
            if (WIFEXITED(status)) {
                std::cout << "\n[*] Target process exited with status: "
                          << WEXITSTATUS(status) << std::endl;
                break;
            }

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                // 여기서 추가 분석 가능
                ptrace(PTRACE_CONT, child_pid, 0, 0);
            } else if (WIFSTOPPED(status)) {
                // 다른 시그널
                ptrace(PTRACE_CONT, child_pid, 0, WSTOPSIG(status));
            }
        }

        std::cout << "[*] Total S-box accesses detected: " << sbox_access_count << std::endl;
    }

    // syscall 트레이싱을 사용한 간단한 모니터링
    void trace_execution() {
        int status;

        std::cout << "[*] Starting execution monitoring..." << std::endl;
        std::cout << "[*] Target will run to completion..." << std::endl;

        // 간단히 실행만 하고 종료 대기
        ptrace(PTRACE_CONT, child_pid, 0, 0);
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            std::cout << "[*] Target process exited with status: "
                      << WEXITSTATUS(status) << std::endl;
        }

        std::cout << "\n=== Summary ===" << std::endl;
        std::cout << "S-box found at: " << sbox_addresses.size() << " location(s)" << std::endl;

        if (!sbox_addresses.empty()) {
            std::cout << "\nNote: To detect actual S-box accesses, you can:" << std::endl;
            std::cout << "  1. Use hardware watchpoints (more complex)" << std::endl;
            std::cout << "  2. Instrument the code with LD_PRELOAD" << std::endl;
            std::cout << "  3. Use Intel PIN or DynamoRIO for dynamic instrumentation" << std::endl;
            std::cout << "  4. Modify the target binary to add callbacks" << std::endl;
        }
    }

    // 디버거 시작
    bool start() {
        child_pid = fork();

        if (child_pid == 0) {
            // 자식 프로세스: 타겟 프로그램 실행
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execl(target_program.c_str(), target_program.c_str(), NULL);

            // execl 실패시
            std::cerr << "Failed to execute target program: " << target_program << std::endl;
            exit(1);
        } else if (child_pid > 0) {
            // 부모 프로세스: 디버거
            int status;
            waitpid(child_pid, &status, 0);

            std::cout << "[*] Target process started (PID: " << child_pid << ")" << std::endl;

            // SBOX 주소 찾기
            std::cout << "[*] Searching for S-box in memory..." << std::endl;
            if (find_sbox_in_memory()) {
                std::cout << "[+] S-box found!" << std::endl;
            } else {
                std::cout << "[!] S-box not found in memory." << std::endl;
            }

            // 실행 모니터링
            trace_execution();

            return true;
        } else {
            std::cerr << "Fork failed!" << std::endl;
            return false;
        }

        return true;
    }
};

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options] <target_program>" << std::endl;
    std::cout << "\nOptions:" << std::endl;
    std::cout << "  -v    Verbose output" << std::endl;
    std::cout << "\nExample:" << std::endl;
    std::cout << "  " << prog_name << " ./aes_test" << std::endl;
    std::cout << "  " << prog_name << " -v ./aes_test" << std::endl;
    std::cout << "\nDescription:" << std::endl;
    std::cout << "  Simple ptrace-based debugger to detect AES S-box in memory" << std::endl;
    std::cout << "  This is a learning tool - Phase 1: Finding S-box in memory" << std::endl;
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    std::string target_program;

    // 인자 파싱
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-v") {
            verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            target_program = arg;
        }
    }

    if (target_program.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    std::cout << "=== AES S-box Debugger v2 ===" << std::endl;
    std::cout << "[*] Target: " << target_program << std::endl;
    std::cout << "[*] Mode: S-box Memory Detection" << std::endl;
    std::cout << std::endl;

    AESSboxDebugger debugger(target_program, verbose);

    if (!debugger.start()) {
        return 1;
    }

    return 0;
}
