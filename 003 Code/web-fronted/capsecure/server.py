from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib, json, secrets, time
import requests

# == [통합 추가] 회원가입 -> 체인코드 -> 블록해시 -> 세션키 ==
import os, random, base64, hmac, hashlib, subprocess, re

from flask_cors import CORS
from pathlib import Path

app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": "*"}})

# 데모 인메모리 저장 (운영은 DB 사용)
USERS = {}         # username -> {pwd_hash, name, email, createdAt, map_id}
TOKENS = {}        # token -> username
ASCII_MAPS = {}    # map_id -> { "map": { "32":"45", ... }, "version":1 }

PRINTABLE = [i for i in range(32,127)]

def seeded_shuffle(seed:bytes):
    # 간단한 결정론 셔플 (xorshift 유사)
    import struct
    x = struct.unpack("<I", hashlib.sha256(seed).digest()[:4])[0]
    arr = PRINTABLE[:]
    for i in range(len(arr)-1,0,-1):
        x ^= (x<<13)&0xffffffff; x ^= (x>>17); x ^= (x<<5)&0xffffffff
        j = x % (i+1)
        arr[i],arr[j] = arr[j],arr[i]
    return arr

def create_ascii_map_for_user(username:str):
    version = 1
    shuffled = seeded_shuffle(f"user:{username}:v{version}".encode())
    mapping = { str(PRINTABLE[i]) : shuffled[i] for i in range(len(PRINTABLE)) }
    map_id  = hashlib.sha256(f"{username}:{version}".encode()).hexdigest()[:16]
    ASCII_MAPS[map_id] = {"map": mapping, "version": version}

    # 체인에는 원문 대신 해시 기록 (운영: Fabric submitTransaction)
    map_hash = hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest()
    tx_id = "0x"+secrets.token_hex(8)
    print(f"[CHAIN] PutAsciiMap user={username} mapId={map_id} hash={map_hash} v={version} tx={tx_id}")
    return map_id, tx_id

@app.post("/api/signup")
def api_signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    name     = (data.get("name") or "").strip()
    email    = (data.get("email") or "").strip()

    # 간단 검증
    if not username or not password or not name or not email:
        return jsonify(error="필수 항목 누락"), 400
    if not (5 <= len(username) <= 10) or not username.isalnum():
        return jsonify(error="아이디 형식이 올바르지 않습니다."), 400
    if not (5 <= len(password) <= 10):
        return jsonify(error="비밀번호 길이(5~10자)를 확인하세요."), 400
    if username in USERS:
        return jsonify(error="이미 존재하는 아이디입니다."), 409

    USERS[username] = {
        "pwd_hash": generate_password_hash(password),
        "name": name, "email": email, "createdAt": time.time()
    }
    map_id, tx_id = create_ascii_map_for_user(username)
    USERS[username]["map_id"] = map_id

    return jsonify(ok=True, asciiMapId=map_id, txId=tx_id), 201

@app.post("/api/login")
def api_login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    u = USERS.get(username)
    if not u or not check_password_hash(u["pwd_hash"], password):
        return jsonify(error="아이디/비밀번호 확인"), 401
    token = secrets.token_urlsafe(32)
    TOKENS[token] = username
    return jsonify(token=token)

@app.get("/api/me/ascii-map")
def api_map():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return jsonify(error="인증 필요"), 401
    token = auth.split(" ",1)[1]
    username = TOKENS.get(token)
    if not username: return jsonify(error="인증 만료"), 401
    # map_id = USERS[username]["map_id"]
    # payload = ASCII_MAPS.get(map_id)
    # return jsonify(asciiMap=payload["map"], version=payload["version"])
    entry = USERS.get(username, {})
    map_id = entry.get("map_id")
    # 1) 메모리 저장형(데모)인 경우: 기존 로직 유지
    if map_id and not map_id.startswith("fs:"):
        payload = ASCII_MAPS.get(map_id)
        return jsonify(asciiMap=payload["map"], version=payload["version"])
    # 2) 파일 저장형(통합 플로우): encryption-client/<user>/ascii_mapping.json 읽어서 변환
    try:
        p = (REPO_ROOT / "encryption-client" / username / "ascii_mapping.json")
        with open(p, "r", encoding="utf-8") as f:
            char2char = json.load(f)            # 예: {"a":"Q", ...}
        # app.py가 기대하는 포맷: {"32":45, ...} (문자 코드포인트 숫자 매핑)
        num_map = { str(ord(k)) : ord(v) for k, v in char2char.items() }
        return jsonify(asciiMap=num_map, version=1)
    except FileNotFoundError:
        return jsonify(error="매핑 파일 없음"), 404
    except Exception as e:
        return jsonify(error=f"매핑 로드 실패: {e}"), 500

#========
CHANNEL_NAME = "userchannel"

def _project_dir() -> Path:
    # server.py 위치: web-fronted/capsecure/server.py
    # 프로젝트 상위(web-fronted)로 올라감
    return Path(__file__).resolve().parents[1]

def _find_repo_root(start: Path) -> Path:
    # 상위로 올라가며 fabric-samples 루트(= test-network 폴더 존재)를 찾음
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "test-network").exists():
            return cur
        cur = cur.parent
    env = os.getenv("FABRIC_SAMPLES_ROOT")
    return Path(env).resolve() if env else start.resolve()

PROJECT_DIR = _project_dir()                      # .../fabric-samples/web-fronted
REPO_ROOT   = _find_repo_root(PROJECT_DIR)        # .../fabric-samples
ENC_DIR     = REPO_ROOT / "encryption-client"     # ascii_mapping.json 표준 위치
BC_CLIENT   = PROJECT_DIR / "blockchain_client"   # 현재 존재하는 폴더

def _generate_ascii_mapping():
    src = list(range(32, 127))
    dst = src.copy()
    random.SystemRandom().shuffle(dst)
    return {chr(s): chr(d) for s, d in zip(src, dst)}

def _save_mapping_json(user_id: str, mapping: dict) -> Path:
    user_dir = ENC_DIR / user_id
    user_dir.mkdir(parents=True, exist_ok=True)
    p = user_dir / "ascii_mapping.json"
    with open(p, "w", encoding="utf-8") as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2)
    return p

def _derive_user_secret(password: str, user_id: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), user_id.encode(), 100_000, dklen=32)

def _call_submit_mapping(user_id: str) -> str:
    r = subprocess.run(["python3", str(BC_CLIENT / "submit_mapping.py"), user_id],
                       cwd=str(BC_CLIENT), capture_output=True, text=True, env=os.environ)
    if r.returncode != 0:
        raise RuntimeError(f"submit_mapping 실패\n--- STDOUT ---\n{r.stdout}\n--- STDERR ---\n{r.stderr}")

    out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
    m = re.search(r"\b([0-9a-fA-F]{64})\b", out)
    if not m:
        raise RuntimeError(f"txid 추출 실패\n{out}")
    return m.group(1)


def _call_get_block_hash(channel: str) -> bytes:
    r = subprocess.run(["python3", str(BC_CLIENT / "get_block_hash.py"), channel],
                       cwd=str(BC_CLIENT), capture_output=True, text=True, env=os.environ)
    if r.returncode != 0:
        raise RuntimeError(f"get_block_hash 실패\n--- STDOUT ---\n{r.stdout}\n--- STDERR ---\n{r.stderr}")
    return base64.b64decode((r.stdout or "").strip())

# def _make_session_key(user_secret: bytes, txid: str, block_hash: bytes) -> str:
#     material = txid.encode() + block_hash
#     raw = hmac.new(user_secret, material, hashlib.sha256).digest()
#     return base64.urlsafe_b64encode(raw).decode()

def _make_session_key(user_secret: bytes, txid: str, block_hash: bytes) -> str:
    raw = hmac.new(user_secret, txid.encode() + block_hash, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode()

@app.post("/api/register")
def api_register():
    data = request.get_json(force=True)
    user_id = (data.get("user_id") or "").strip()
    password = data.get("password") or ""
    if not user_id or not password:
        return jsonify({"error": "user_id, password 필수"}), 400
    try:
        # ① 매핑 생성 & 저장
        mapping = _generate_ascii_mapping()
        _save_mapping_json(user_id, mapping)
        # ①-추가) 인메모리 사용자도 등록해 api/login이 동작하도록 설정
        from werkzeug.security import generate_password_hash
        if user_id not in USERS:
            USERS[user_id] = {
                "pwd_hash": generate_password_hash(password),
                "name": user_id, "email": "", "createdAt": time.time(),
                "map_id": f"fs:{user_id}"
            }
        # ② 체인코드 저장(SetMapping) + txid 획득
        txid = _call_submit_mapping(user_id)
        # ③ 블록해시(Base64) 획득
        block_hash = _call_get_block_hash(CHANNEL_NAME)
        # ④ 세션키: HMAC(user_secret, txid || blockHash)
        user_secret = _derive_user_secret(password, user_id)
        session_key = _make_session_key(user_secret, txid, block_hash)
        return jsonify({"ok": True, "session_key": session_key, "txid": txid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ========= [/통합추가] =========



@app.errorhandler(404)
def not_found(e):
    # API 경로에서만 JSON, 그 외는 기본 404를 쓰고 싶다면 분기 가능
    if request.path.startswith("/api/"):
        return jsonify(error="Not Found"), 404
    return e, 404

@app.errorhandler(500)
def server_error(e):
    # 디버그 HTML 대신 JSON 에러
    return jsonify(error="서버 내부 오류"), 500    

@app.get("/api/session-key")
def api_session_key():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): 
        return jsonify(error="인증 필요"), 401
    token = auth.split(" ",1)[1]
    username = TOKENS.get(token)
    if not username: 
        return jsonify(error="인증 만료"), 401
    u = USERS.get(username)
    sk = u.get("session_key") if u else None
    if not sk: 
        return jsonify(error="세션키 없음"), 404
    return jsonify(session_key=sk)

# === [추가] Windows 에이전트가 보내는 키 이벤트 수신 ===
@app.post("/api/ingest_raw")
def api_ingest_raw():
    """
    Windows 에이전트가 평문 키를 보냄: {"user_id": "...", "key": "a", "ts": 169...}
    서버가 매핑을 적용하고, (원하면) 서버 측에서 암호화까지 수행.
    """
    data = request.get_json(force=True)
    user_id = (data.get("user_id") or "").strip()
    key     = data.get("key")
    if not user_id or not key:
        return jsonify(error="user_id, key 필수"), 400

    # 파일에서 매핑 로드 (우리가 이미 저장해 둔 경로)
    try:
        p = (REPO_ROOT / "encryption-client" / user_id / "ascii_mapping.json")
        with open(p, "r", encoding="utf-8") as f:
            char2char = json.load(f)  # 예: {"a":"Q", ...}
    except FileNotFoundError:
        return jsonify(error="매핑 파일 없음"), 404

    mapped = char2char.get(key)
    print(f"[INGEST_RAW] user={user_id} key={key!r} -> mapped={mapped!r}")
    if not mapped:
        return jsonify(ok=True, skipped=True)  # 매핑 대상 아님
    
    # === 여기부터 추가 : 8765 UI로 중계 ===
    try:
        requests.post(
            "http://127.0.0.1:8765/api/ingest_raw",
            json={"user_id": user_id, "key": key, "mapped": mapped, "ts": data.get("ts")},
            timeout=0.2
        )
    except Exception as e:
        print("[bridge warn] forward to 8765 failed:", e)
    # === 여기까지 추가 ===

    # (선택) 여기서 서버가 암호화까지 수행하려면 session_key를 저장/호출 구조로 바꿔야 함.
    # 오늘은 데모로 매핑 결과만 로그처럼 되돌려 준다.
    return jsonify(ok=True, mapped=mapped)

@app.post("/api/ingest")
def api_ingest():
    """
    Windows 에이전트가 암호문을 보냄: {"user_id": "...", "ct": "<hex>", "ts": 169...}
    서버는 수신/저장/검증만 수행.
    """
    data = request.get_json(force=True)
    user_id = (data.get("user_id") or "").strip()
    ct_hex  = (data.get("ct") or "").strip()
    if not user_id or not ct_hex:
        return jsonify(error="user_id, ct 필수"), 400

    # TODO: 원하면 블록체인 기록 또는 파일/DB에 적재
    return jsonify(ok=True)


if __name__ == "__main__":
    # 개발용 실행 (운영은 WSGI/uWSGI+NGINX/IIS ReverseProxy 권장)
    app.run(host="0.0.0.0", port=5000, debug=True)