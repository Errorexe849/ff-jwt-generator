import time
import json
import base64
import httpx
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES

from google.protobuf import json_format
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
from google.protobuf.message import Message

# ============================================================
#  PART 1 — FreeFire_pb2 (inlined descriptor)
# ============================================================

try:
    _runtime_version.ValidateProtobufRuntimeVersion(
        _runtime_version.Domain.PUBLIC, 6, 30, 0, "", "FreeFire.proto",
    )
except Exception:
    pass

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0e\x46reeFire.proto"c\n\x08LoginReq\x12\x0f\n\x07open_id\x18\x16 \x01(\t'
    b'\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0blogin_token\x18\x1d '
    b'\x01(\t\x12\x1b\n\x13orign_platform_type\x18\x63 \x01(\t"]\n\x10\x42lacklist'
    b'InfoRes\x12\x1e\n\nban_reason\x18\x01 \x01(\x0e\x32\n.BanReason\x12\x17\n'
    b'\x0f\x65xpire_duration\x18\x02 \x01(\r\x12\x10\n\x08\x62\x61n_time\x18\x03 '
    b'\x01(\r"f\n\x0eLoginQueueInfo\x12\r\n\x05\x61llow\x18\x01 \x01(\x08\x12'
    b'\x16\n\x0equeue_position\x18\x02 \x01(\r\x12\x16\n\x0eneed_wait_secs\x18'
    b'\x03 \x01(\r\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08"\xa0\x03\n\x08'
    b'LoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x04\x12\x13\n\x0block_region'
    b'\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_'
    b'region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t'
    b'\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\x19\n\x11recommend_'
    b'regions\x18\x07 \x03(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl'
    b'\x18\t \x01(\r\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mul'
    b'ator_score\x18\x0b \x01(\r\x12$\n\tblacklist\x18\x0c \x01(\x0b\x32\x11.'
    b'BlacklistInfoRes\x12#\n\nqueue_info\x18\r \x01(\x0b\x32\x0f.LoginQueue'
    b'Info\x12\x0e\n\x06tp_url\x18\x0e \x01(\t\x12\x15\n\rapp_server_id\x18'
    b'\x0f \x01(\r\x12\x0f\n\x07\x61no_url\x18\x10 \x01(\t\x12\x0f\n\x07ip_city'
    b'\x18\x11 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x12 \x01(\t*\xa8\x01\n'
    b'\tBanReason\x12\x16\n\x12\x42\x41N_REASON_UNKNOWN\x10\x00\x12\x1b\n\x17'
    b'\x42\x41N_REASON_IN_GAME_AUTO\x10\x01\x12\x15\n\x11\x42\x41N_REASON_'
    b'REFUND\x10\x02\x12\x15\n\x11\x42\x41N_REASON_OTHERS\x10\x03\x12\x16\n'
    b'\x12\x42\x41N_REASON_SKINMOD\x10\x04\x12 \n\x1b\x42\x41N_REASON_IN_GAME'
    b'_AUTO_NEW\x10\xf6\x07\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "FreeFire_pb2", _globals)

LoginReq = _globals["LoginReq"]
LoginRes = _globals["LoginRes"]

# ============================================================
#  PART 2 — Settings & Cryptography
# ============================================================

MAIN_KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")
RELEASEVERSION = "OB55"
USERAGENT = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
LOGIN_URL = "https://loginbp.ppmainecoonghj.com/"

REGIONAL_CLIENTS = {
    "BD": "https://clientbp.ppmainecoonghj.com",
    "IND": "https://client.ind.freefiremobile.com",
    "BR": "https://client.us.freefiremobile.com",
    "ME": "https://clientbp.ggblueshark.com",
    "default": "https://clientbp.ppmainecoonghj.com"
}

HTTP_LIMITS = httpx.Limits(max_keepalive_connections=20, max_connections=50)
HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_http_client = httpx.Client(limits=HTTP_LIMITS, timeout=HTTP_TIMEOUT, verify=False)

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# ============================================================
#  PART 3 — Response Parsers
# ============================================================

def try_parse_login_res(data: bytes):
    try:
        msg = LoginRes()
        msg.ParseFromString(data)
        if msg.account_id and msg.account_id > 0:
            return json.loads(json_format.MessageToJson(msg))
    except Exception:
        pass
    return None

def extract_login_res(raw: bytes) -> dict:
    parsed = try_parse_login_res(raw)
    if parsed:
        return parsed

    idx = 0
    while True:
        idx = raw.find(b"\x08", idx)
        if idx == -1:
            break
        parsed = try_parse_login_res(raw[idx:])
        if parsed:
            return parsed
        idx += 1

    jwt_marker = raw.find(b"eyJhbGciOiJIUzI1NiIs")
    if jwt_marker != -1:
        for i in range(jwt_marker - 1, max(jwt_marker - 300, -1), -1):
            if raw[i] == 0x42:
                parsed = try_parse_login_res(raw[i:])
                if parsed:
                    return parsed
                break

    raise Exception(f"Could not parse LoginRes from server response")

def decode_jwt_payload(jwt_token: str):
    try:
        parts = jwt_token.split(".")
        if len(parts) >= 2:
            payload = parts[1]
            payload += "=" * (-len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        pass
    return {}

def encode_varint(n: int) -> bytes:
    res = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            res.append(b | 0x80)
        else:
            res.append(b)
            break
    return bytes(res)

def parse_player_personal_show(data: bytes):
    """Zero-dependency parser for GetPlayerPersonalShow basicInfo"""
    i = 0
    basic_bytes = None
    while i < len(data):
        tag = data[i]
        i += 1
        wire = tag & 0x07
        field_num = tag >> 3
        if wire == 2:
            length = 0
            shift = 0
            while True:
                b = data[i]
                i += 1
                length |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            val = data[i:i+length]
            i += length
            if field_num == 1:
                basic_bytes = val
                break
        elif wire == 0:
            while data[i] & 0x80:
                i += 1
            i += 1
        else:
            break

    if not basic_bytes:
        return {}

    j = 0
    res = {}
    while j < len(basic_bytes):
        tag = basic_bytes[j]
        j += 1
        wire = tag & 0x07
        field_num = tag >> 3
        if wire == 0:
            val = 0
            shift = 0
            while True:
                b = basic_bytes[j]
                j += 1
                val |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            if field_num == 1: res["account_id"] = val
            elif field_num == 6: res["level"] = val
            elif field_num == 7: res["exp"] = val
        elif wire == 2:
            length = 0
            shift = 0
            while True:
                b = basic_bytes[j]
                j += 1
                length |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            s_val = basic_bytes[j:j+length]
            j += length
            if field_num == 3: res["nickname"] = s_val.decode("utf-8", errors="ignore")
            elif field_num == 5: res["region"] = s_val.decode("utf-8", errors="ignore")
        else:
            break
    return res

# ============================================================
#  PART 4 — Core Auth & Profile Pipeline
# ============================================================

def get_access_token(uid: str, password: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = _http_client.post(url, data=payload, headers=headers)
    data = resp.json()
    return data.get("access_token"), data.get("open_id")

def fetch_player_profile(jwt_token: str, account_id: int, server_url: str = None, region: str = "BD"):
    req_bytes = b"\x08" + encode_varint(account_id) + b"\x10\x07"
    enc_payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, req_bytes)

    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)",
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
    }

    candidate_urls = []
    if server_url:
        candidate_urls.append(server_url.rstrip("/") + "/GetPlayerPersonalShow")
    candidate_urls.append(REGIONAL_CLIENTS.get(region, REGIONAL_CLIENTS["default"]) + "/GetPlayerPersonalShow")
    candidate_urls.append(REGIONAL_CLIENTS["default"] + "/GetPlayerPersonalShow")

    for url in candidate_urls:
        try:
            r = _http_client.post(url, data=enc_payload, headers=headers)
            if r.status_code == 200 and len(r.content) > 30:
                parsed = parse_player_personal_show(r.content)
                if parsed:
                    return parsed
        except Exception:
            continue
    return {}

def generate_jwt_with_info(uid: str, password: str):
    start_time = time.time()

    token_val, open_id = get_access_token(uid, password)
    if not token_val or not open_id:
        raise Exception("Invalid UID or Password — access token not received")

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4",
    })
    proto_bytes = json_to_proto(body, LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    headers = {
        "User-Agent": USERAGENT,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": "1789534056",
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "Releaseversion": RELEASEVERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "PlAy_VeR": "1.132.1",
        "Ob_VeR": RELEASEVERSION,
    }

    resp = _http_client.post(f"{LOGIN_URL}MajorLogin", data=payload, headers=headers)
    msg = extract_login_res(resp.content)

    jwt_token = msg.get("token", "")
    real_uid = msg.get("accountId")
    server_url = msg.get("serverUrl", "")
    region = msg.get("lockRegion") or msg.get("notiRegion")

    # Decode JWT payload for extra verification
    decoded_jwt = decode_jwt_payload(jwt_token)
    if not real_uid and decoded_jwt.get("account_id"):
        real_uid = decoded_jwt["account_id"]
    if not region and decoded_jwt.get("lock_region"):
        region = decoded_jwt["lock_region"]

    # Fetch player details (level, nickname, exp)
    profile = {}
    if jwt_token and real_uid:
        try:
            profile = fetch_player_profile(jwt_token, int(real_uid), server_url, region or "BD")
        except Exception:
            pass

    elapsed = time.time() - start_time

    return {
        "status": "success",
        "uid": str(uid),
        "account_id": str(real_uid) if real_uid else str(uid),
        "real_uid": str(real_uid) if real_uid else str(uid),
        "nickname": profile.get("nickname") or decoded_jwt.get("nickname") or "N/A",
        "level": profile.get("level") or 1,
        "exp": profile.get("exp") or 0,
        "region": profile.get("region") or region or "BD",
        "access_token": token_val,
        "open_id": open_id,
        "token": jwt_token,
        "jwt_token": jwt_token,
        "time": f"{elapsed:.2f}s"
    }

# ============================================================
#  PART 5 — Flask App & Endpoints
# ============================================================

app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "online",
        "version": RELEASEVERSION,
        "endpoint": "/token?uid=UID&password=PASS"
    }), 200

@app.route("/token", methods=["GET", "POST"])
def get_jwt_token():
    uid = request.args.get("uid") or (request.json.get("uid") if request.is_json else None)
    password = request.args.get("password") or (request.json.get("password") if request.is_json else None)

    if not uid or not password:
        return jsonify({
            "status": "error",
            "error": "Both uid and password parameters are required"
        }), 400

    try:
        token_data = generate_jwt_with_info(uid, password)
        return jsonify(token_data), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": f"Failed to generate token: {str(e)}"
        }), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
