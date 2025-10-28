# 003 Code

폴더 구성

| 폴더명 | 내용 |
|--------|------|
| `test-network/` | Fabric 네트워크 설정 및 Docker Compose 스크립트 |
| `chaincode/` | 사용자별 ASCII 매핑 테이블 저장용 체인코드 |
| `web-fronted/` | Flask 기반 웹 대시보드 및 로그인/관리 페이지 |
| `encryption-client/` | 키보드 입력 암호화 클라이언트 모듈 |
| `tools/` | 테스트 스크립트 및 유틸리티 (예: save_mapping.py, submit_mapping.py) |


---

# 주요 특징
- Hyperledger Fabric 기반 분산 원장 저장
- ChaCha20 기반 스트림 암호화
- HMAC-SHA256 세션 키 생성
- ASCII 매핑 재정의를 통한 사용자 맞춤 암호화
- 로그/아티팩트 자동 제외 ('.gitignore' 설정 완료)

## 참고
- `organizations/`, `crypto-config/`, `channel-artifacts/`, `*.block`, `*.tx`, `node_modules/` 등  
  네트워크 실행 시 자동 생성되는 파일은 .gitignore로 제외되어 있습니다.

민감한 인증서나 블록체인 아티팩트 파일은 포함되지 않습니다.

