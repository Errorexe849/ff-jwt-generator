import sys
import os
import time
import json
import base64
import requests
import urllib3
from flask import Flask, request, jsonify
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Dynamic import setup for protobuf helpers from existing folders without modifying them
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
JXE_DIR = os.path.join(CURRENT_DIR, "JXE_INFO_API_OB55 (1)")
JWT_FULL_DIR = os.path.join(CURRENT_DIR, "JWT-API-FULL-main", "JWT-API-FULL-main")
FF_JWT_DIR = os.path.join(CURRENT_DIR, "ff-jwt-token-main", "ff-jwt-token-main")

for p in [JXE_DIR, JWT_FULL_DIR, FF_JWT_DIR]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

# Keys and Config
MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID = "100067"
RELEASE_VERSION = "OB55"

REGION_SERVERS = {
    "BD": "https://clientbp.ppmainecoonghj.com",
    "IND": "https://client.ind.freefiremobile.com",
    "BR": "https://client.us.freefiremobile.com",
    "ME": "https://clientbp.ggblueshark.com",
    "SAC": "https://clientbp.ggblueshark.com",
    "NA": "https://clientbp.ggblueshark.com",
    "default": "https://clientbp.ppmainecoonghj.com"
}

LOGIN_URLS = [
    "https://loginbp.ppmainecoonghj.com/MajorLogin",
    "https://loginbp.ggpolarbear.com/MajorLogin",
    "https://loginbp.ggblueshark.com/MajorLogin"
]

def pad_bytes(data: bytes) -> bytes:
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def encrypt_aes_cbc(data: bytes, key: bytes = MAIN_KEY, iv: bytes = MAIN_IV) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad_bytes(data))

def decrypt_aes_cbc(data: bytes, key: bytes = MAIN_KEY, iv: bytes = MAIN_IV):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        pad_len = decrypted[-1]
        if 1 <= pad_len <= AES.block_size:
            return decrypted[:-pad_len]
        return decrypted
    except Exception:
        return None

def fetch_access_token(uid: str, password: str):
    """Step 1: Obtain OAuth guest access token"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.42(SM-A136B ;Android 9;en;US;app 1.132.1 2024061806;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "Keep-Alive",
    }
    body = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": CLIENT_SECRET,
        "client_id": CLIENT_ID
    }
    resp = requests.post(url, headers=headers, data=body, verify=False, timeout=12)
    if resp.status_code == 200:
        res_json = resp.json()
        return {
            "access_token": res_json.get("access_token"),
            "open_id": res_json.get("open_id")
        }
    return None

def perform_major_login(uid: str, access_token: str, open_id: str):
    """Step 2: Authenticate and retrieve JWT token"""
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
        "Accept-Encoding": "gzip"
    }

    # Attempt method A: Using FreeFire_pb2 LoginReq if available
    payload = None
    try:
        import FreeFire_pb2
        req = FreeFire_pb2.LoginReq()
        req.open_id = str(open_id)
        req.open_id_type = "4"
        req.login_token = str(access_token)
        req.orign_platform_type = "4"
        payload = encrypt_aes_cbc(req.SerializeToString())
    except Exception:
        pass

    # Method B fallback: my_pb2 GameData
    if not payload:
        try:
            import my_pb2
            gd = my_pb2.GameData()
            gd.open_id = str(open_id)
            gd.access_token = str(access_token)
            gd.platform_type = 4
            gd.game_name = "free fire"
            payload = encrypt_aes_cbc(gd.SerializeToString())
        except Exception:
            pass

    for login_url in LOGIN_URLS:
        try:
            r = requests.post(login_url, headers=headers, data=payload, verify=False, timeout=12)
            if r.status_code == 200 and len(r.content) > 10:
                # Parse protobuf response
                try:
                    import FreeFire_pb2
                    res = FreeFire_pb2.LoginRes()
                    res.ParseFromString(r.content)
                    if res.token:
                        return {
                            "jwt_token": res.token,
                            "account_id": str(res.account_id),
                            "region": res.lock_region or res.noti_region or "IND",
                            "server_url": res.server_url
                        }
                except Exception:
                    pass

                # Parse output_pb2 fallback
                try:
                    import output_pb2
                    msg = output_pb2.Lokesh()
                    for offset in range(0, min(len(r.content), 200)):
                        try:
                            msg.ParseFromString(r.content[offset:])
                            if msg.token:
                                return {
                                    "jwt_token": msg.token,
                                    "account_id": str(msg.account_id),
                                    "region": msg.region or "IND",
                                    "server_url": REGION_SERVERS.get(msg.region, REGION_SERVERS["default"])
                                }
                        except Exception:
                            continue
                except Exception:
                    pass
        except Exception:
            continue

    return None

def fetch_player_profile(jwt_token: str, account_id: str, server_url: str, region: str = "IND"):
    """Step 3: Retrieve level, nickname, exp using GetPlayerPersonalShow"""
    endpoint = (server_url or REGION_SERVERS.get(region, REGION_SERVERS["default"])).rstrip("/") + "/GetPlayerPersonalShow"
    
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)",
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
        "Accept-Encoding": "gzip"
    }

    payload = None
    try:
        import main_pb2
        req = main_pb2.GetPlayerPersonalShow()
        req.a = int(account_id)
        req.b = 7
        payload = encrypt_aes_cbc(req.SerializeToString())
    except Exception:
        try:
            import PlayerPersonalShow_pb2
            req = PlayerPersonalShow_pb2.request()
            req.accountId = int(account_id)
            req.callSignSrc = 7
            payload = encrypt_aes_cbc(req.SerializeToString())
        except Exception:
            pass

    if payload:
        try:
            r = requests.post(endpoint, data=payload, headers=headers, verify=False, timeout=12)
            if r.status_code == 200 and len(r.content) > 0:
                # Try parsing with AccountPersonalShow_pb2
                try:
                    import AccountPersonalShow_pb2
                    acc_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
                    acc_info.ParseFromString(r.content)
                    basic = acc_info.basicInfo
                    return {
                        "level": getattr(basic, "level", None),
                        "nickname": getattr(basic, "nickname", None),
                        "exp": getattr(basic, "exp", None)
                    }
                except Exception:
                    pass

                # Try parsing with PlayerPersonalShow_pb2
                try:
                    import PlayerPersonalShow_pb2
                    res = PlayerPersonalShow_pb2.response()
                    res.ParseFromString(r.content)
                    basic = res.basicinfo
                    return {
                        "level": getattr(basic, "level", None),
                        "nickname": getattr(basic, "nickname", None),
                        "exp": getattr(basic, "exp", None)
                    }
                except Exception:
                    pass
        except Exception:
            pass

    return {"level": None, "nickname": None, "exp": None}

def generate_full_account_data(uid: str, password: str):
    """Orchestrates token generation + full profile extraction"""
    token_auth = fetch_access_token(uid, password)
    if not token_auth or not token_auth.get("access_token"):
        return {"status": "error", "message": "Failed to get access token"}

    access_token = token_auth["access_token"]
    open_id = token_auth["open_id"]

    login_info = perform_major_login(uid, access_token, open_id)
    jwt_token = login_info.get("jwt_token") if login_info else None
    account_id = login_info.get("account_id") if login_info else str(uid)
    region = login_info.get("region", "IND") if login_info else "IND"
    server_url = login_info.get("server_url") if login_info else REGION_SERVERS.get(region, REGION_SERVERS["default"])

    profile = {"level": None, "nickname": None, "exp": None}
    if jwt_token and account_id:
        profile = fetch_player_profile(jwt_token, account_id, server_url, region)

    return {
        "status": "success",
        "level": profile.get("level"),
        "nickname": profile.get("nickname"),
        "exp": profile.get("exp"),
        "uid": str(uid),
        "account_id": account_id,
        "access_token": access_token,
        "jwt_token": jwt_token,
        "region": region
    }

app = Flask(__name__)
try:
    from flask_cors import CORS
    CORS(app)
except Exception:
    pass

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "online",
        "endpoint": "/token?uid=<UID>&password=<PASSWORD>",
        "target_fields": ["level", "nickname", "exp", "uid", "account_id", "access_token", "jwt_token"]
    })

@app.route("/token", methods=["GET", "POST"])
def token_route():
    uid = request.args.get("uid") or (request.json.get("uid") if request.is_json else None)
    password = request.args.get("password") or (request.json.get("password") if request.is_json else None)

    if not uid or not password:
        return jsonify({"status": "error", "message": "Missing uid or password parameter"}), 400

    result = generate_full_account_data(uid, password)
    return jsonify(result)

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        cli_uid = sys.argv[1]
        cli_pw = sys.argv[2]
        print(f"[*] Processing UID: {cli_uid}...")
        data = generate_full_account_data(cli_uid, cli_pw)
        print(json.dumps(data, indent=2))
    else:
        port = int(sys.argv[1]) if len(sys.argv) == 2 else 5000
        print(f"[*] Starting server on port {port}...")
        app.run(host="0.0.0.0", port=port, debug=False)
