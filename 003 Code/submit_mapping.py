import json
import subprocess
import os
import sys

def submit_mapping(user_id):
    base = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base, "encryption-client", user_id, "ascii_mapping.json")
    
    with open(filepath, "r", encoding="utf-8") as f:
        mapping_data = json.load(f)
    
    args = json.dumps(["SetMapping", user_id, json.dumps(mapping_data)])

    ORDERER_CA = f"{base}/test-network/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"
    PEER_TLS_ROOTCERT_FILE = f"{base}/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"

    
    cmd = [
        "peer", "chaincode", "invoke",
        "-o", "localhost:7050",
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--tls", "--cafile", ORDERER_CA,
        "-C", "userchannel",
        "-n", "ascii_cc",
        "--peerAddresses", "localhost:7051",
        "--tlsRootCertFiles", PEER_TLS_ROOTCERT_FILE,
        "-c", f'{{"function":"SetMapping","Args":{args}}}'
    ]
    
    print("블록체인에 Ascii Mapping Value Table 저장 중...")
    subprocess.run(cmd, check=True)

def query_mapping(user_id):
    cmd = [
        "peer", "chaincode", "query",
        "-C", "userchannel",
        "-n", "ascii_cc",
        "-c", f'{{"function":"GetMapping","Args":["{user_id}"]}}'
    ]
    
    print("저장된 매핑 데이터 조회 중...")
    subprocess.run(cmd, check=True)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python3 submit_mapping.py [user_id]")
    else:
        user_id = sys.argv[1]
        submit_mapping(user_id)
        query_mapping(user_id)