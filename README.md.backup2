# AES S-box Debugger

ptrace를 사용하여 AES 암호 연산의 S-box 접근을 감지하는 간단한 디버거입니다.

## 개요

이 프로젝트는 암호 연산을 분석하고 학습하기 위한 도구입니다. 현재는 AES S-box 테이블을 메모리에서 찾아내는 기본 기능을 구현했습니다.

**타겟:** 직접 구현된 AES 암호화 코드 (OpenSSL 같은 라이브러리는 타겟이 아닙니다)

## 빠른 시작 (Quick Start)

```bash
# 1. 클론 (또는 소스 다운로드)
cd dbg_test

# 2. 빌드
make

# 3. 실행
make test
```

**예상 출력:**
```
[*] Target process started (PID: xxxxx)
[*] Searching for S-box in memory...
[+] Found SBOX at address: 0x5xxxxxxxxxxxxx
[+] S-box found!
[*] Starting execution monitoring...
...
S-box found at: 1 location(s)
```

## 빌드 및 사용 방법

### 빌드
```bash
make              # 디버거 v2와 테스트 프로그램 빌드
make clean        # build/ 디렉토리 삭제
make help         # 사용 가능한 명령어 확인
```

모든 빌드 결과물은 `build/` 디렉토리에 생성됩니다.

### 실행
```bash
# 추천: Makefile 사용
make test         # 디버거 v2 실행 (권장)
make test-v1      # 디버거 v1 실행 (싱글스텝, 느림)

# 직접 실행
./build/aes_sbox_debugger_v2 ./build/aes256_test
```

## 동작 원리 상세 설명

### 1. ptrace 기반 프로세스 제어

#### fork()와 PTRACE_TRACEME
```
부모 프로세스 (디버거)
    |
    +-- fork() --> 자식 프로세스 (타겟 프로그램)
                       |
                       +-- ptrace(PTRACE_TRACEME)  // "나를 추적해줘"
                       |
                       +-- execl(target_program)   // AES 프로그램 실행
```

**동작 순서:**
1. 디버거가 `fork()`로 자식 프로세스 생성
2. 자식이 `ptrace(PTRACE_TRACEME, 0, 0, 0)` 호출
   - 이 시스템콜은 "부모 프로세스가 나를 디버그하도록 허용"을 의미
3. 자식이 `execl()`로 타겟 프로그램 실행
4. execl 직후 자식은 자동으로 **SIGTRAP**으로 정지
5. 부모는 `waitpid()`로 자식의 정지를 감지

#### 핵심 ptrace 시스템콜

```c
// 메모리 읽기 (8바이트씩)
long data = ptrace(PTRACE_PEEKDATA, child_pid, address, NULL);

// 프로세스 계속 실행
ptrace(PTRACE_CONT, child_pid, 0, 0);

// 레지스터 읽기
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
```

### 2. S-box 메모리 탐지 알고리즘

#### Step 1: /proc/[pid]/maps 분석
```
# cat /proc/12345/maps
5555555a4000-5555555a5000 r--p 00020000 08:01 12345  /path/to/aes_test
5555555a5000-5555555a6000 r-xp 00021000 08:01 12345  /path/to/aes_test
                          ^^^^
                          권한: r--p (읽기 전용, private)
                                r-xp (읽기/실행)
```

**메모리 영역 타입:**
- `r-xp`: 코드 세그먼트 (실행 가능)
- `r--p`: 읽기 전용 데이터 (여기에 const SBOX가 있을 가능성 높음)
- `rw-p`: 읽기/쓰기 데이터
- `---p`: 접근 불가 (가드 페이지)

#### Step 2: 메모리 스캔

```c
for (unsigned long addr = start; addr < end - 256; addr += 8) {
    uint8_t buffer[256];

    // 8바이트씩 읽기 (ptrace는 word 단위로만 읽음)
    for (int i = 0; i < 256; i += sizeof(long)) {
        long data = ptrace(PTRACE_PEEKDATA, child_pid, addr + i, NULL);
        memcpy(&buffer[i], &data, sizeof(long));
    }

    // 256바이트가 AES S-box와 일치하는지 확인
    if (memcmp(buffer, SBOX, 256) == 0) {
        printf("Found S-box at 0x%lx\n", addr);
    }
}
```

**왜 8바이트 정렬로 스캔하는가?**
- ptrace(PTRACE_PEEKDATA)는 `sizeof(long)` (64비트에서 8바이트) 단위로만 읽음
- 메모리 정렬 최적화 (대부분의 상수 배열은 8바이트 정렬됨)
- 성능 향상 (1바이트씩 스캔하면 너무 느림)

#### Step 3: 패턴 매칭

**AES S-box 시작 패턴:**
```
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, ...
```

이 256바이트 패턴을 `memcmp()`로 정확히 매칭합니다.

### 3. 프로세스 상태 전이

```
타겟 프로세스 상태:

RUNNING ──(시그널)──> STOPPED ──(PTRACE_CONT)──> RUNNING
   │                      │
   │                      └─> 디버거가 메모리/레지스터 읽을 수 있음
   │
   └──(정상 종료)──> EXITED (WIFEXITED)
```

### 4. 현재 구현의 한계

**문제: S-box를 찾았지만 실제 접근은 감지 못함**

이유:
1. `PTRACE_CONT`는 프로세스를 중단 없이 실행
2. S-box 메모리 읽기는 일반적인 메모리 접근 (시그널 발생 안 함)
3. 싱글 스텝(`PTRACE_SINGLESTEP`)은 너무 느림 (명령어마다 트랩)

**해결 방법 (향후 구현):**

#### 방법 1: 하드웨어 Watchpoint (DR0-DR7 레지스터)
```
CPU의 디버그 레지스터:
- DR0~DR3: 4개의 주소 저장 (watchpoint 위치)
- DR7: 제어 레지스터 (읽기/쓰기/실행 감지 설정)

동작:
1. DR0 = S-box 주소 (0x5555555a4020)
2. DR7 = 읽기 접근 감지 설정
3. CPU가 해당 주소 읽으면 자동으로 SIGTRAP 발생
4. 디버거가 레지스터 확인 -> input/output 추출
```

#### 방법 2: 함수 브레이크포인트
```
sub_bytes 함수에 INT3 (0xCC) 삽입:

원본:     55 48 89 e5 ...  (함수 시작)
수정:     CC 48 89 e5 ...  (0xCC = INT3 = 브레이크포인트)

동작:
1. sub_bytes 호출 -> INT3 실행 -> SIGTRAP
2. 디버거가 레지스터 덤프
3. 원본 명령어(55) 복원 후 1명령어 실행
4. 다시 INT3 삽입
```

### 5. 메모리 레이아웃 예시

```
타겟 프로그램 메모리 맵:

0x555555554000 ┌─────────────────┐
               │  .text (코드)   │  r-xp
0x555555558000 ├─────────────────┤
               │  .rodata        │  r--p  <-- const SBOX[256]이 여기!
0x55555555a000 ├─────────────────┤         주소: 0x555555559020
               │  .data          │  rw-p
0x55555555c000 ├─────────────────┤
               │  .bss           │  rw-p
0x555555560000 ├─────────────────┤
               │  heap           │  rw-p
               ⋮
0x7ffffffde000 ├─────────────────┤
               │  stack          │  rw-p
0x7ffffffff000 └─────────────────┘
```

**왜 OpenSSL에서는 S-box를 못 찾는가?**
1. OpenSSL은 AES-NI (하드웨어 가속) 사용 가능 -> S-box 테이블 안 씀
2. 동적 S-box 생성 (런타임에 계산)
3. T-table 최적화 (S-box를 다른 형태로 변환)
4. 암호화된 형태로 저장 후 복호화해서 사용

### 6. 디버깅 세션 플로우

```
[디버거]                [타겟 프로세스]
   |                          |
   fork() -----------------> 생성됨
   |                          |
   |                    PTRACE_TRACEME
   |                          |
   |                      execl("aes_test")
   |                          |
   waitpid() <----------- SIGTRAP (정지)
   |
   /proc/PID/maps 읽기
   |
   PTRACE_PEEKDATA로 메모리 스캔
   |  (0x555555559000부터 256바이트씩)
   |
   S-box 발견! (0x555555559020)
   |
   PTRACE_CONT -------------> 실행 재개
   |                          |
   |                      암호화 수행
   |                      (S-box 접근 중...)
   |                          |
   waitpid() <----------- EXITED (종료)
   |
   통계 출력
```

## 현재 구현된 기능

### Phase 1: S-box 메모리 탐지 ✅
- ptrace를 사용하여 타겟 프로세스 attach
- /proc/[pid]/maps 파싱하여 메모리 영역 식별
- PTRACE_PEEKDATA로 8바이트씩 메모리 읽기
- 256바이트 패턴 매칭으로 S-box 테이블 찾기
- S-box의 정확한 메모리 주소 출력

## 향후 추가할 기능

### Phase 2: S-box 접근 감지 (계획중)
다음 단계에서 구현할 기능들:

1. **하드웨어 브레이크포인트 (Watchpoint)**
   - x86-64 디버그 레지스터 (DR0-DR7) 사용
   - S-box 메모리 영역에 읽기 watchpoint 설정
   - 접근 시 SIGTRAP 발생 -> input/output 값 추출
   - 4개 주소까지 동시 감시 가능 (DR0~DR3)

2. **함수 브레이크포인트**
   - `sub_bytes` 함수 시작 주소에 INT3 (0xCC) 삽입
   - 함수 진입/종료 시 레지스터 상태 캡처
   - 스택 트레이스 추출

3. **통계 및 분석**
   - S-box 접근 패턴 분석
   - 접근 빈도 통계 (어떤 인덱스가 많이 사용되는지)
   - 타이밍 정보 수집 (캐시 타이밍 공격 시뮬레이션)

### Phase 3: 다른 암호 연산 지원 (계획중)
- DES S-box (8개의 S-box, 각 64 엔트리)
- RSA modular exponentiation 추적
- ECC point operations 추적

## 프로젝트 구조

```
.
├── aes_sbox_debugger.cpp       # v1: 싱글 스텝 방식 (느림)
├── aes_sbox_debugger_v2.cpp    # v2: 메모리 스캔만 (현재 버전)
├── test/
│   ├── CustomImpl/
│   │   └── symmetric/
│   │       └── custom_impl_symmetric_aes256_ecb_from_scratch.cpp  # 타겟
│   └── openssl/
│       └── symmetric/
│           └── openssl_symmetric_aes_lib_test.cpp  # 참고용 (S-box 못 찾음)
├── Makefile
├── README.md
└── demo.sh
```

## 학습 목표

1. **ptrace 시스템 콜 이해**
   - `PTRACE_TRACEME`: 자식이 부모에게 추적 허용
   - `PTRACE_CONT`: 중단된 프로세스 재개
   - `PTRACE_PEEKDATA`: 메모리 읽기 (word 단위)
   - `PTRACE_POKEDATA`: 메모리 쓰기
   - `PTRACE_GETREGS`: CPU 레지스터 읽기
   - `PTRACE_SETREGS`: CPU 레지스터 쓰기
   - `PTRACE_SINGLESTEP`: 한 명령어 실행 후 정지

2. **프로세스 메모리 구조**
   - `/proc/[pid]/maps`: 메모리 맵 정보
   - 텍스트 세그먼트 (.text): 코드
   - 읽기 전용 데이터 (.rodata): 상수 (S-box가 여기!)
   - 데이터 세그먼트 (.data): 초기화된 전역 변수
   - BSS 세그먼트 (.bss): 초기화 안 된 전역 변수
   - 메모리 권한 플래그: r (읽기), w (쓰기), x (실행), p (private)

3. **암호 알고리즘 내부 구조**
   - AES S-box의 역할: 비선형 치환으로 혼돈(confusion) 제공
   - SubBytes 연산: `state[i] = SBOX[state[i]]`
   - 라운드 키 확장에서도 S-box 사용 (sub_word)
   - AES-256은 14라운드 -> S-box가 224번 호출됨 (16바이트 × 14라운드)

4. **디버거 동작 원리**
   - 프로세스 제어: fork/exec 모델
   - 시그널 처리: SIGTRAP, SIGSTOP
   - 소프트웨어 브레이크포인트: INT3 (0xCC) 삽입
   - 하드웨어 브레이크포인트: CPU 디버그 레지스터 (DR0-DR7)

## 기술적 세부사항

### ptrace의 한계

1. **성능 오버헤드**
   - 싱글 스텝은 명령어마다 컨텍스트 스위칭
   - AES 한 번 실행에 수천 개의 명령어 -> 너무 느림

2. **메모리 읽기 제약**
   - word (8바이트) 단위로만 읽기 가능
   - 정렬되지 않은 주소 읽기 어려움

3. **권한 제한**
   - 일부 시스템에서 ptrace 비활성화 (/proc/sys/kernel/yama/ptrace_scope)
   - 다른 사용자의 프로세스 추적 불가

### 메모리 스캔 최적화

현재 구현: O(n) 선형 스캔
- 8바이트 단위로 증가 (정렬된 데이터 가정)
- 읽기 전용 영역만 스캔 (쓰기 가능한 영역은 스킵)

개선 가능:
- ELF 섹션 헤더 직접 파싱 (.rodata 섹션만 스캔)
- DWARF 디버그 정보 사용 (SBOX 심볼 직접 찾기)

## 주의사항

- 이 도구는 **교육 및 연구 목적**으로만 사용하세요
- 타겟 프로그램은 `-g -O0` 옵션으로 컴파일된 것을 권장합니다
  - `-g`: 디버그 심볼 포함
  - `-O0`: 최적화 비활성화 (코드가 소스와 일치)
- ptrace는 관리자 권한이 필요할 수 있습니다
  - `sudo sysctl kernel.yama.ptrace_scope=0` (임시)
- 직접 구현된 AES만 타겟으로 합니다 (OpenSSL 제외)

## 예제 출력

```
=== AES S-box Debugger v2 ===
[*] Target: ./test/CustomImpl/symmetric/aes256_test
[*] Mode: S-box Memory Detection

[*] Target process started (PID: 12345)
[*] Searching for S-box in memory...
[+] Found SBOX at address: 0x5555555a4020
[+] S-box found!
[*] Starting execution monitoring...
[*] Target will run to completion...
Plaintext : 6bc1bee22e409f96e93d7e117393172a
Ciphertext: f3eed1bdb5d2a03c064b5a7e3db181f8
Recovered : 6bc1bee22e409f96e93d7e117393172a
[*] Target process exited with status: 0

=== Summary ===
S-box found at: 1 location(s)

Note: To detect actual S-box accesses, you can:
  1. Use hardware watchpoints (more complex)
  2. Instrument the code with LD_PRELOAD
  3. Use Intel PIN or DynamoRIO for dynamic instrumentation
  4. Modify the target binary to add callbacks
```

## 다음에 구현할 기능

현재는 S-box를 메모리에서 찾는 단계까지 완료했습니다. 실제 S-box 접근을 감지하려면 다음 기능들을 추가할 수 있습니다:

### Phase 2-A: 하드웨어 Watchpoint (추천) 🎯
CPU의 디버그 레지스터를 사용하여 메모리 접근을 하드웨어 레벨에서 감지합니다.

**구현 방법:**
```c
// DR0에 S-box 주소 설정
ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[0]), sbox_addr);

// DR7에 읽기 watchpoint 활성화
unsigned long dr7 = (1 << 0) |  // Local exact breakpoint #0
                    (3 << 16) | // Break on read/write
                    (3 << 18);  // 4 bytes
ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[7]), dr7);
```

**장점:**
- ✅ 하드웨어 지원으로 오버헤드 거의 없음
- ✅ 정확한 메모리 접근 감지
- ✅ Input/Output 값 추출 가능

**단점:**
- ⚠️ 구현이 복잡함
- ⚠️ 4개 주소만 동시 감시 가능 (DR0~DR3)

**활용:**
- S-box 접근 횟수 카운팅
- 접근 패턴 분석 (어떤 인덱스가 많이 사용되는지)
- 타이밍 정보 수집 (캐시 타이밍 공격 시뮬레이션)

### Phase 2-B: 함수 브레이크포인트
`sub_bytes` 함수에 소프트웨어 브레이크포인트(INT3)를 삽입하여 함수 호출을 감지합니다.

**구현 방법:**
1. 함수 주소 찾기 (심볼 테이블 또는 패턴 매칭)
2. 첫 바이트를 0xCC(INT3)로 교체
3. SIGTRAP 발생 시 원본 명령어 복원 후 실행
4. 다시 INT3 삽입

**활용:**
- 함수 호출 횟수 카운팅
- 함수 인자/반환값 추적
- 스택 트레이스 수집

### Phase 3: 다른 암호 알고리즘 지원
- **DES S-box**: 8개의 S-box, 각 64 엔트리
- **RSA 연산**: modular exponentiation 추적
- **ECC 연산**: point multiplication 추적

### 다른 접근 방법 (참고)

**Dynamic Binary Instrumentation (DBI):**
- Intel PIN, DynamoRIO, Frida 사용
- 모든 메모리 접근 추적 가능
- 성능 오버헤드 있음
- ptrace보다 강력하지만 복잡함

**LD_PRELOAD Hook:**
- 함수 호출만 인터셉트 가능
- 구현이 간단
- 정적 데이터 접근(배열)은 감지 불가 → S-box에는 부적합

## 참고 자료

- [ptrace man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Intel® 64 and IA-32 Architectures Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
  - Volume 3B, Chapter 17: Debug, Branch Profile, TSC, and Intel® Resource Director Technology (Intel® RDT) Features
- [AES (Advanced Encryption Standard)](https://csrc.nist.gov/publications/detail/fips/197/final)
- [/proc filesystem documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)

## 라이선스

Educational and Research Use Only
