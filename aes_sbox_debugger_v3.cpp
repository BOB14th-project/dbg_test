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
#include <map>
#include <algorithm>
#include <algorithm>

// AES S-box 테이블
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

// DR7 레지스터 비트 필드 정의
#define DR7_LOCAL_ENABLE_0    (1UL << 0)
#define DR7_GLOBAL_ENABLE_0   (1UL << 1)
#define DR7_LEN_1_BYTE        (0UL << 18)
#define DR7_LEN_2_BYTE        (1UL << 18)
#define DR7_LEN_4_BYTE        (3UL << 18)
#define DR7_LEN_8_BYTE        (2UL << 18)
#define DR7_BREAK_ON_EXEC     (0UL << 16)
#define DR7_BREAK_ON_WRITE    (1UL << 16)
#define DR7_BREAK_ON_RW       (3UL << 16)

class AESSboxDebugger {
private:
    pid_t child_pid;
    std::string target_program;
    std::vector<unsigned long> sbox_addresses;
    int sbox_access_count = 0;
    bool verbose = false;
    bool use_watchpoint = true;

    // 통계
    std::map<uint8_t, int> access_frequency;  // S-box 인덱스별 접근 빈도

public:
    AESSboxDebugger(const std::string& program, bool v = false, bool wp = true)
        : child_pid(-1), target_program(program), verbose(v), use_watchpoint(wp) {}

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

                // 메모리 영역 읽기
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

    // 하드웨어 watchpoint 설정 (DR0-DR7 레지스터 사용)
    bool set_hardware_watchpoint(unsigned long address) {
        // DR0에 watchpoint 주소 설정
        if (ptrace(PTRACE_POKEUSER, child_pid,
                   offsetof(struct user, u_debugreg[0]), address) == -1) {
            std::cerr << "Failed to set DR0: " << strerror(errno) << std::endl;
            return false;
        }

        // DR7 설정: 읽기/쓰기 감지, 1바이트, 로컬 enable
        unsigned long dr7 = 0;
        dr7 |= DR7_LOCAL_ENABLE_0;      // DR0 활성화
        dr7 |= DR7_BREAK_ON_RW;         // 읽기/쓰기 모두 감지
        dr7 |= DR7_LEN_1_BYTE;          // 1바이트 감시

        if (ptrace(PTRACE_POKEUSER, child_pid,
                   offsetof(struct user, u_debugreg[7]), dr7) == -1) {
            std::cerr << "Failed to set DR7: " << strerror(errno) << std::endl;
            return false;
        }

        if (verbose) {
            std::cout << "[*] Hardware watchpoint set at 0x"
                      << std::hex << address << std::dec << std::endl;
        }

        return true;
    }

    // S-box 접근 분석
    void analyze_sbox_access(unsigned long rip, unsigned long sbox_addr) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
            return;
        }

        // 메모리에서 접근된 주소 주변 읽기 (어떤 인덱스인지 추정)
        // 실제로는 명령어를 디스어셈블해야 정확하지만, 간단한 휴리스틱 사용

        sbox_access_count++;

        // 레지스터들 검사하여 S-box 범위 내 값 찾기
        unsigned long registers[] = {
            regs.rax, regs.rbx, regs.rcx, regs.rdx,
            regs.rsi, regs.rdi, regs.r8, regs.r9,
            regs.r10, regs.r11, regs.r12, regs.r13,
            regs.r14, regs.r15
        };

        const char* reg_names[] = {
            "rax", "rbx", "rcx", "rdx",
            "rsi", "rdi", "r8", "r9",
            "r10", "r11", "r12", "r13",
            "r14", "r15"
        };

        std::cout << "[" << std::setw(4) << sbox_access_count << "] S-box access detected!" << std::endl;
        std::cout << "       RIP: 0x" << std::hex << rip << std::dec << std::endl;

        // S-box 관련 레지스터 출력
        for (size_t i = 0; i < sizeof(registers) / sizeof(registers[0]); i++) {
            if (registers[i] >= sbox_addr && registers[i] < sbox_addr + 256) {
                uint8_t index = registers[i] - sbox_addr;
                std::cout << "       " << reg_names[i] << " points to S-box[0x"
                          << std::hex << (int)index << std::dec
                          << "] = 0x" << std::hex << (int)SBOX[index] << std::dec << std::endl;

                access_frequency[index]++;
            }
        }

        // 하위 8비트 값들도 확인 (인덱스일 가능성)
        if (verbose) {
            std::cout << "       Potential indices in registers:" << std::endl;
            for (size_t i = 0; i < sizeof(registers) / sizeof(registers[0]); i++) {
                uint8_t low_byte = registers[i] & 0xFF;
                if (low_byte < 256) {
                    std::cout << "         " << reg_names[i] << " (low byte): 0x"
                              << std::hex << (int)low_byte << std::dec << std::endl;
                }
            }
        }
    }

    // 하드웨어 watchpoint를 사용한 추적
    void trace_with_watchpoint() {
        if (sbox_addresses.empty()) {
            std::cerr << "[!] No S-box found, cannot set watchpoint" << std::endl;
            return;
        }

        unsigned long sbox_addr = sbox_addresses[0];

        std::cout << "[*] Setting hardware watchpoint at S-box address..." << std::endl;
        if (!set_hardware_watchpoint(sbox_addr)) {
            std::cerr << "[!] Failed to set hardware watchpoint" << std::endl;
            std::cerr << "[!] Note: Hardware watchpoints may not be fully supported in WSL" << std::endl;
            std::cerr << "[!] Falling back to simple monitoring..." << std::endl;
            trace_simple();
            return;
        }

        std::cout << "[*] Starting execution with watchpoint monitoring..." << std::endl;

        int status;
        ptrace(PTRACE_CONT, child_pid, 0, 0);

        while (waitpid(child_pid, &status, 0) > 0) {
            if (WIFEXITED(status)) {
                std::cout << "\n[*] Target process exited with status: "
                          << WEXITSTATUS(status) << std::endl;
                break;
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);

                if (sig == SIGTRAP) {
                    // SIGTRAP: watchpoint 또는 브레이크포인트
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

                    // DR6 레지스터 확인 (어떤 디버그 조건이 발생했는지)
                    unsigned long dr6 = ptrace(PTRACE_PEEKUSER, child_pid,
                                               offsetof(struct user, u_debugreg[6]), 0);

                    if (dr6 & 0x1) {  // B0 비트: DR0 watchpoint hit
                        analyze_sbox_access(regs.rip, sbox_addr);

                        // DR6 클리어
                        ptrace(PTRACE_POKEUSER, child_pid,
                               offsetof(struct user, u_debugreg[6]), 0);
                    }

                    ptrace(PTRACE_CONT, child_pid, 0, 0);
                } else {
                    // 다른 시그널은 그대로 전달
                    ptrace(PTRACE_CONT, child_pid, 0, sig);
                }
            }
        }

        print_statistics();
    }

    // 간단한 모니터링 (watchpoint 실패시)
    void trace_simple() {
        std::cout << "[*] Running target program..." << std::endl;

        ptrace(PTRACE_CONT, child_pid, 0, 0);

        int status;
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            std::cout << "[*] Target process exited with status: "
                      << WEXITSTATUS(status) << std::endl;
        }
    }

    // 통계 출력
    void print_statistics() {
        std::cout << "\n=== Statistics ===" << std::endl;
        std::cout << "Total S-box accesses: " << sbox_access_count << std::endl;

        if (!access_frequency.empty() && verbose) {
            std::cout << "\nMost accessed S-box indices:" << std::endl;

            // 빈도순 정렬을 위한 벡터
            std::vector<std::pair<uint8_t, int>> sorted_freq(
                access_frequency.begin(), access_frequency.end());

            std::sort(sorted_freq.begin(), sorted_freq.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });

            int count = 0;
            for (const auto& pair : sorted_freq) {
                if (count++ >= 10) break;  // 상위 10개만
                std::cout << "  S-box[0x" << std::hex << (int)pair.first << std::dec
                          << "] = 0x" << std::hex << (int)SBOX[pair.first] << std::dec
                          << " : " << pair.second << " times" << std::endl;
            }
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
                return false;
            }

            // 실행 모니터링
            if (use_watchpoint) {
                trace_with_watchpoint();
            } else {
                trace_simple();
            }

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
    std::cout << "  -v         Verbose output" << std::endl;
    std::cout << "  -s         Simple mode (no watchpoint)" << std::endl;
    std::cout << "  -h         Show this help" << std::endl;
    std::cout << "\nExample:" << std::endl;
    std::cout << "  " << prog_name << " ./build/aes256_test" << std::endl;
    std::cout << "  " << prog_name << " -v ./build/aes256_test" << std::endl;
    std::cout << "\nDescription:" << std::endl;
    std::cout << "  Advanced ptrace-based debugger to detect AES S-box accesses" << std::endl;
    std::cout << "  Uses hardware watchpoints (DR0-DR7) for precise memory access detection" << std::endl;
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    bool use_watchpoint = true;
    std::string target_program;

    // 인자 파싱
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-v") {
            verbose = true;
        } else if (arg == "-s") {
            use_watchpoint = false;
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

    std::cout << "=== AES S-box Debugger v3 (Hardware Watchpoint) ===" << std::endl;
    std::cout << "[*] Target: " << target_program << std::endl;
    std::cout << "[*] Mode: " << (use_watchpoint ? "Hardware Watchpoint" : "Simple") << std::endl;
    std::cout << std::endl;

    AESSboxDebugger debugger(target_program, verbose, use_watchpoint);

    if (!debugger.start()) {
        return 1;
    }

    return 0;
}
