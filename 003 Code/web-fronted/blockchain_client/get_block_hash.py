import json, os, subprocess, sys
from pathlib import Path

def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "test-network").exists():
            return cur
        cur = cur.parent
    return start.resolve()

BASE = Path(__file__).resolve().parent
ROOT = find_repo_root(BASE)
NET  = ROOT / "test-network"

ENV = {
    **os.environ,
    "FABRIC_CFG_PATH": str(ROOT / "config"),
    "CORE_PEER_LOCALMSPID": "Org1MSP",
    "CORE_PEER_TLS_ENABLED": "true",
    "CORE_PEER_MSPCONFIGPATH": str(NET / "organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"),
    "CORE_PEER_TLS_ROOTCERT_FILE": str(NET / "organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"),
    "CORE_PEER_ADDRESS": "localhost:7051",
}

def get_latest_block_hash(channel_name="userchannel") -> str:
    # getinfo는 피어 원장 조회(일반적으로 이걸로 충분)
    r = subprocess.run(["peer","channel","getinfo","-c",channel_name], env=ENV, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"[getinfo 실패]\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}")
    # 최신 버전은 JSON 그대로 반환
    out = r.stdout.strip()
    try:
        info = json.loads(out)
    except Exception:
        # 일부 버전은 "Blockchain info: {...}" 형태
        info = json.loads(out.split("Blockchain info: ",1)[1])
    return info["currentBlockHash"]

if __name__ == "__main__":
    ch = sys.argv[1] if len(sys.argv) > 1 else "userchannel"
    print(get_latest_block_hash(ch))

    # """
    # 최신 블록의 해시 값을 반환합니다.
    # 환경변수는 사전에 설정되어 있어야 합니다.
    # """
    # try:
    #     # 최신 블록 정보를 가져오는 명령어 실행
    #     subprocess.run([
    #         "peer", "channel", "fetch", "newest", "newest.block",
    #         "-c", channel_name,
    #         "--output", "localhost:7050",
    #         "--tls",
    #         "--cafile", "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
    #     ], check=True)
        
    #     # 블록 정보 조회
    #     result = subprocess.run([
    #         "peer", "channel", "getinfo", "-c", channel_name
    #     ], capture_output=True, text=True, check=True)

    #     output = result.stdout.strip()
    #     block_info = json.loads(output.split("Blockchain info: ")[1])
    #     return block_info["currentBlockHash"]
    
    # except Exception as e:
    #     print(f"블록 해시 조회 실패: ", str(e))
    #     return ""