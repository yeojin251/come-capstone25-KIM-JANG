# 한밭대학교 컴퓨터공학과 김앤장팀

**팀 구성**
- 20227130 장하린 
- 20227129 장여진
- 20227127 김봉경

## <u>Teamate</u> Project Background
- ### 필요성
  - 키로깅과 같이 사용자 입력값을 노리는 공격이 증가하면서 입력 단계의 보안 강화 필요함
  - 단순한 탐지나 차단 중심의 기존 보안 방식은 실시간 데이터 유출을 방어하기 어려움
  - 안전한 입력 환경을 위해 실시간 암호화와 무결성 검증이 가능한 기술적 대안이 요구됨
- ### 기존 해결책의 문제점
  - 기존 보안 키보드는 특정 브라우저나 환경에서만 작동하는 경우가 많아 범용성이 떨어짐
  - 브라우저 내부 스크립트 조작을 통해 입력값을 가로채는 공격에는 대응이 어려움
  
## System Design
<img width="942" height="450" alt="image" src="https://github.com/user-attachments/assets/7d6baf8b-6210-430d-9676-05189cf6ebc7" />

  - ### System Requirements
    - Python 3.10
    - Flask (서버 및 API 통신)
    - Hyperledger Fabric 2.5+ (블록체인 네트워크 구성)
    - Pynput (Windows 키 입력 이벤트 감지)
    - Docker & Compose (Fabric 네트워크 컨테이너 관리)
    - Node.js (대시보드 프론트엔드 서버)
    - SQLite, LevelDB (백엔드 DB)
    - HTML, CSS, JavaScript (프론트엔드 페이지 구성)
    
## Case Study
  - ### Description
  
  
## Conclusion
  - ### 본 시스템은 키 입력 단계에서부터 암호화를 수행하여 기존 보안 키보드의 구조적 한계를 보완하고 블록체인 기반 저장으로 무결성과 신뢰성을 강화하였다.
  - ### 피싱 및 키로깅 공격에 대한 근본적인 방어 체계를 제시하며 향우 금융기관, 공공기관 등 다양한 환경에 적용 가능한 경량 실시간 입력 보안 솔루션으로 발전할 수 있다.
  
## Project Outcome
- ### 2025년 전자공학회 하계종합학술대회 
