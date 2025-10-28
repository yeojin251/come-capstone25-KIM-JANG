import json, subprocess, os, sys, base64, re
from pathlib import Path

# === 프로젝트 루트 자동 탐색: 'test-network'를 만날 때까지 상향 ===
def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "test-network").exists():
            return cur
        cur = cur.parent
    return start.resolve()

BASE = Path(__file__).resolve().parent      # web_fronted/blockchain_client
ROOT = find_repo_root(BASE)                 # fabric-samples 루트 기대
NET  = ROOT / "test-network"

# === 공통 경로 ===
ORDERER_ADDR = "localhost:7050"
ORDERER_CAFILE = NET / "organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"

# === 피어 설정(Org1) ===

# PEER_ADDR = "localhost:7051"
# PEER_TLS_ROOTCERT = NET / "organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
# MSP_PATH = NET / "organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"

# Org1 / Org2 / (옵션) Org3 피어 주소+TLS 루트
PEERS = [
    ("localhost:7051", NET / "organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"),
    ("localhost:9051", NET / "organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"),
]
# Org3가 있다면 자동 추가 (샘플 네트워크를 확장한 경우)
org3_ca = NET / "organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt"
if org3_ca.exists():
    PEERS.append(("localhost:11051", org3_ca))

# 기본 서명 주체는 Org1 Admin (필요 시 변경)
MSP_PATH = NET / "organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"

ENV = {
    **os.environ,
    "FABRIC_CFG_PATH": str(ROOT / "config"),  # test-network 표준
    "CORE_PEER_LOCALMSPID": "Org1MSP",
    "CORE_PEER_TLS_ENABLED": "true",
    "CORE_PEER_MSPCONFIGPATH": str(MSP_PATH),
    "CORE_PEER_TLS_ROOTCERT_FILE": str(PEERS[0][1]),  # 기본: Org1 피어
    "CORE_PEER_ADDRESS": PEERS[0][0],  # 기본: Org1 피어
}

CHANNEL = "userchannel"
CC_NAME = "ascii_cc"

# === (중요) 매핑 암호화: ChaCha20-Poly1305 예시 ===
# * cryptography 필요: pip install cryptography
def encrypt_mapping_chacha20(mapping_json_str: str, key32: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import os
    aead = ChaCha20Poly1305(key32)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, mapping_json_str.encode("utf-8"), b"")
    return base64.b64encode(nonce + ct).decode()

def derive_user_key(user_id: str) -> bytes:
    # 가입 시 서버에서 만든 사용자 시크릿(또는 PBKDF2(password, user_id))을 읽어오는 자리에 맞춰 교체
    # 데모용: 고정 파생(반드시 교체하세요)
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", user_id.encode(), b"capstone-salt", 100_000, dklen=32)


def submit_mapping(user_id: str) -> str:
        # 1) 평문 매핑 로드
    mapping_path = ROOT / "encryption-client" / user_id / "ascii_mapping.json"
    with open(mapping_path, "r", encoding="utf-8") as f:
        mapping_data = json.load(f)
    mapping_json = json.dumps(mapping_data, ensure_ascii=False)

    # 2) 암호화(ChaCha20-Poly1305) → base64 문자열
    key = derive_user_key(user_id)  # 또는 서버/DB/세션에서 전달받은 키
    cipher_text_b64 = encrypt_mapping_chacha20(mapping_json, key)

    # 3) 인보크(payload) 구성
    args = json.dumps(["SetMapping", user_id, cipher_text_b64])
    payload = f'{{"function":"SetMapping","Args":{args}}}'

    # 4) 동시 엔도스용 인자 구성
    cmd = [
        "peer","chaincode","invoke",
        "-o", ORDERER_ADDR,
        "--ordererTLSHostnameOverride","orderer.example.com",
        "--tls","--cafile", str(ORDERER_CAFILE),
        "-C", CHANNEL, "-n", CC_NAME,
        # "--peerAddresses", PEER_ADDR,
        # "--tlsRootCertFiles", str(PEER_TLS_ROOTCERT),
        "-c", payload,
        "--waitForEvent",
    ]
    for addr, ca in PEERS:
        cmd += ["--peerAddresses", addr, "--tlsRootCertFiles", str(ca)]

    # 5) 인보크 실행
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"[invoke 실패]\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}")

    # out = (r.stdout + "\n" + r.stderr)
    out = (r.stdout or "") + "\n" + (r.stderr or "")
    out = re.sub(r'\x1b\[[0-9;]*m', '', out)

    # 여러 포맷을 커버하는 정규식
    patterns = [
        r'txid\s*\[([0-9a-fA-F]{64})\]',     # txid [abcd...]
        r'txid\s*:\s*([0-9a-fA-F]{64})',     # txid: abcd...
        r'Transaction ID\s*[:\-]?\s*([0-9a-fA-F]{64})',
        r'\b([0-9a-fA-F]{64})\b'             # 최후 수단: 첫 64-hex
    ]

    txid = ""
    for pat in patterns:
        m = re.search(pat, out, re.IGNORECASE)
        if m:
            txid = m.group(1); break
    if not txid:
        # 디버깅에 도움: 실패 시 raw 출력 일부를 에러에 포함
        raise SystemExit(f"[txid 추출 실패]\n{out}")
    # m = re.search(r'txid[:\s]+([0-9a-fA-F]{64})', out)
    # txid = m.group(1) if m else ""
    # print(txid)  # 상위(Flask)가 읽어 세션키 엔트로피로 사용
    # return txid

    print(txid)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python3 submit_mapping.py [user_id]")
        sys.exit(1)
    submit_mapping(sys.argv[1])

    # #base = os.path.dirname(os.path.abspath(__file__))
    # #filepath = os.path.join(base, "encryption-client", user_id, "ascii_mapping.json")
    
    # with open(filepath, "r", encoding="utf-8") as f:
    #     mapping_data = json.load(f)
    
    # args = json.dumps(["SetMapping", user_id, json.dumps(mapping_data)])

    # ORDERER_CA = f"{base}/test-network/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"
    # PEER_TLS_ROOTCERT_FILE = f"{base}/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"

    
    # cmd = [
    #     "peer", "chaincode", "invoke",
    #     "-o", "localhost:7050",
    #     "--ordererTLSHostnameOverride", "orderer.example.com",
    #     "--tls", "--cafile", ORDERER_CA,
    #     "-C", "userchannel",
    #     "-n", "ascii_cc",
    #     "--peerAddresses", "localhost:7051",
    #     "--tlsRootCertFiles", PEER_TLS_ROOTCERT_FILE,
    #     "-c", f'{{"function":"SetMapping","Args":{args}}}'
    # ]
    
    # print("블록체인에 Ascii Mapping Value Table 저장 중...")
    # subprocess.run(cmd, check=True)

def query_mapping(user_id):
    cmd = [
        "peer", "chaincode", "query",
        "-C", "userchannel",
        "-n", "ascii_cc",
        "-c", f'{{"function":"GetMapping","Args":["{user_id}"]}}'
    ]
    
    print("저장된 매핑 데이터 조회 중...")
    subprocess.run(cmd, check=True)

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("사용법: python3 submit_mapping.py [user_id]")
#     else:
#         user_id = sys.argv[1]
#         submit_mapping(user_id)
#         query_mapping(user_id)