# Custom Cryptography Implementations

이 디렉터리는 표준 라이브러리 호출 대신 순수 C++로 작성한 고전(비양자) 암호 알고리즘 실험 코드를 모읍니다. 각 하위 폴더는 `tests/api_call/` 구조와 동일하게 `symmetric`, `public_key`, `signature`, `hash_kdf`, `entropy`, `protocol` 케이스로 나뉘며, 알고리즘별 학습용 레퍼런스 또는 취약 시나리오 재현을 목적으로 합니다.

## 디렉터리 구조
- `symmetric/` – 예: 직접 구현한 AES-256 ECB 및 ChaCha20 스트림 암호
- `public_key/` – 예: 60비트대 모듈러를 갖는 RSA 키 생성과 암복호 실험
- `signature/` – 예: SHA-256 기반 RSA 서명/검증 절차 재현
- `hash_kdf/` – 예: HMAC-SHA256 기반 PBKDF2 파생 키 계산
- `entropy/` – 예: LCG 기반 약한 난수 생성기, RNG 품질 비교
- `protocol/` – 예: 최소 TLS 핸드셰이크 흐름 모형, 취약한 협상 시나리오

## 사용 가이드
1. 각 서브 폴더의 `*.cpp` 소스는 표준 라이브러리에만 의존합니다. 예: `g++ -std=c++17 custom_impl_symmetric_aes256_ecb_from_scratch.cpp -o aes256_ecb`.
2. 실제 라이브러리 대응 테스트와 비교할 수 있도록 동일한 입력/출력 사례를 유지합니다.
3. 취약 케이스를 재현하는 경우, README 또는 주석에 의도와 기대 결과를 명시합니다.

기존 `tests/api_call/` 예제와 짝을 이루도록 설계하여, 라이브러리 호출 vs. 직접 구현을 비교 분석할 수 있게 하는 것이 목표입니다.
