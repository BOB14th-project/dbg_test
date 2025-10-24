# Interactive CLI Examples

`tests/NeedCliInput/` 디렉터리는 사용자가 CLI에서 선택지를 입력해야 동작하는 상호작용형 예제 모음을 담고 있습니다. 현재는 OpenSSL 분류 체계를 그대로 따라 `symmetric`, `public_key`, `signature`, `hash_kdf`, `entropy`, `protocol` 여섯 개 케이스에 대한 C++ 데모가 포함되어 있습니다.

## 공통 동작 방식
각 실행 파일은 다음과 같은 메뉴 루프를 갖습니다.

```
0: 종료
1: 데모 실행
2: 오류 시뮬레이션
```

- `0`을 입력하면 프로그램이 종료됩니다.
- `1`을 입력하면 해당 카테고리의 핵심 기능(예: 문자열 XOR 암호화, RSA 암·복호, PBKDF2 루프 등)이 실행되며 필요한 경우 추가 입력을 요구합니다.
- `2`를 입력하면 CLI에 오류 메시지를 출력한 뒤 메뉴 선택 단계로 되돌아갑니다.

## 빌드 예시
모든 소스는 C++17 표준과 표준 라이브러리에만 의존합니다. 예:

```
g++ -std=c++17 tests/NeedCliInput/openssl/symmetric/need_cli_input_openssl_symmetric_manual_xor_cli.cpp -o manual_xor_cli
```

같은 방식으로 다른 카테고리의 소스도 빌드할 수 있습니다.
