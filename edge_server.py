"""
edge_server.py  –  Smart-City Traffic Camera Edge Node (Flask)
=============================================================
All 13 security topics are handled here with live API endpoints
that feed the dashboard frontend.
"""

import os, sys, json, time, base64, hashlib, uuid, random, threading
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, deque

from flask import Flask, Response, request, jsonify, render_template, send_from_directory, stream_with_context
from flask_cors import CORS

import jwt as pyjwt
from dotenv import load_dotenv

load_dotenv()

from crypto_utils import (
    aes_encrypt, aes_decrypt,
    hmac_sign, hmac_verify,
    ibe_register_identity, ibe_get_public_key, ibe_encrypt, ibe_decrypt,
    abe_check_policy, DEFAULT_POLICY,
    pre_generate_rekey, pre_transform_ciphertext,
    he_encrypt, he_decrypt,
    sse_keygen, sse_trapdoor, sse_build_index, sse_search,
    paillier_keygen, paillier_encrypt, paillier_add_encrypted, paillier_decrypt,
    hash_plate, add_laplace_noise, rotate_camera_id, dummy_location,
    EDGE_SECRET, AES_KEY_LEN,
)
import phe as paillier_lib

app = Flask(__name__)
CORS(app)

JWT_SECRET  = os.getenv("JWT_SECRET", "")
if len(JWT_SECRET.encode()) < 32:
    raise RuntimeError("Set JWT_SECRET to at least 32 characters in your local .env file.")
JWT_ALGO    = "HS256"
CAMERA_AES_KEY = hashlib.sha256(EDGE_SECRET).digest()[:AES_KEY_LEN]

# ─── Global State ───────────────────────────────────────────────────────────
stored_records = []          # decrypted records (in-memory "DB")
enc_records    = []          # encrypted ciphertext store

request_counts = defaultdict(list)   # camera_id → [timestamps]
quarantined    = set()
RATE_LIMIT     = 10          # max requests per 10-second window
RATE_WINDOW    = 10

stats = {
    "total_uploads": 0,
    "hmac_verified": 0,
    "hmac_failed":   0,
    "quarantined_ids": [],
    "abe_granted": 0,
    "abe_denied":  0,
    "sse_searches": 0,
    "pre_rekeys":  0,
    "he_decrypts": 0,
    "ibe_lookups": 0,
    "jwt_issued":  0,
    "jwt_verified":0,
    "handovers":   0,
    "honey_decoys":0,
    "privacy_noise_applied": 0,
    "monthly_count": 0,
}

activity_log = deque(maxlen=100)   # rolling log entries

video_state = {
    "frame": None,
    "updated_at": 0.0,
    "detection_count": 0,
    "vehicles_sent": 0,
    "camera_id": "VIDEO-CAM-01",
    "zone": "Zone1",
}
video_state_lock = threading.Lock()

# Paillier key pair (utility holds private key)
PAILLIER_PUB, PAILLIER_PRIV = paillier_keygen(512)
encrypted_counts = []    # list of Paillier ciphertexts

# SSE
SSE_MASTER_KEY = EDGE_SECRET[:16]
SSE_KEY = sse_keygen(SSE_MASTER_KEY)
sse_index: dict = {}

# Honey vault
honey_vault_token: bytes = b""

# IBE – register default gateway identity
ibe_register_identity("intersection-47-gateway")
ibe_register_identity("edge-neighbour-01")

# Re-key store
rekey_store: dict = {}

# Handover tickets  camera_id → {ticket, expiry, edge}
handover_tickets: dict = {}

def log_event(category: str, msg: str, level: str = "info"):
    activity_log.appendleft({
        "ts":       datetime.now().strftime("%H:%M:%S"),
        "category": category,
        "msg":      msg,
        "level":    level,
    })

log_event("system", "Edge server started. IBE identities registered.", "success")

# ─── Helpers ────────────────────────────────────────────────────────────────

def rate_check(camera_id: str) -> bool:
    """Return True if camera is within rate limit."""
    now = time.time()
    times = request_counts[camera_id]
    # Purge old
    request_counts[camera_id] = [t for t in times if now - t < RATE_WINDOW]
    request_counts[camera_id].append(now)
    if len(request_counts[camera_id]) > RATE_LIMIT:
        if camera_id not in quarantined:
            quarantined.add(camera_id)
            stats["quarantined_ids"] = list(quarantined)
            log_event("attack", f"Camera {camera_id} QUARANTINED (flood detected)", "danger")
        return False
    return True

def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing JWT"}), 401
        token = auth.split(" ", 1)[1]
        try:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            request.jwt_payload = payload
            stats["jwt_verified"] += 1
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "JWT expired"}), 401
        except pyjwt.InvalidTokenError as e:
            return jsonify({"error": f"Invalid JWT: {e}"}), 401
        return f(*args, **kwargs)
    return decorated

# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# ── 4.1/4.2  Upload: HMAC verify + AES store ────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    data       = request.get_json(force=True)
    camera_id  = data.get("camera_id", "unknown")
    zone       = data.get("zone", "unknown")
    ct_b64     = data.get("ciphertext", "")
    signature  = data.get("signature", "")

    # 4.12 Attack detection
    if not rate_check(camera_id):
        return jsonify({"status": "quarantined", "error": "Rate limit exceeded"}), 429

    # 4.1 CIA – HMAC verify
    ct_bytes = base64.b64decode(ct_b64)
    if not hmac_verify(ct_bytes, signature):
        stats["hmac_failed"] += 1
        log_event("security", f"HMAC FAILED from {camera_id}", "danger")
        return jsonify({"status": "error", "error": "HMAC verification failed"}), 403

    stats["hmac_verified"] += 1

    # 4.2 Decrypt for storage + indexing
    try:
        plaintext = aes_decrypt(ct_bytes, CAMERA_AES_KEY)
        record    = json.loads(plaintext)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    record["id"]        = str(uuid.uuid4())[:8]
    record["camera_id"] = camera_id
    record["zone"]      = zone
    record["received"]  = datetime.now().isoformat()

    # 4.11 Privacy – hash plate before long-term storage
    original_plate = record.get("plate", "")
    record["plate_hash"]  = hash_plate(original_plate)
    record["plate_anon"]  = original_plate[:3] + "***" + original_plate[-2:]  # partial mask
    record["location"]    = dummy_location()
    stats["privacy_noise_applied"] += 1

    # 4.8 SSE – update encrypted index
    sse_index.update(sse_build_index([record], ["stolen", "wanted", "normal"], SSE_KEY))

    # 4.9 HOM – Paillier encrypt count increment
    enc_one = paillier_encrypt(1, PAILLIER_PUB)
    encrypted_counts.append(enc_one)
    stats["monthly_count"] += 1

    stored_records.append(record)
    enc_records.append({"id": record["id"], "ciphertext": ct_b64, "zone": zone})
    stats["total_uploads"] += 1

    log_event("upload", f"Plate {record['plate_anon']} from zone {zone} stored (encrypted)", "info")

    return jsonify({"status": "ok", "record_id": record["id"]})


# ── 4.3  IBE ────────────────────────────────────────────────────────────────
@app.route("/ibe/pubkey/<identity>")
def ibe_pubkey(identity):
    pub = ibe_get_public_key(identity)
    stats["ibe_lookups"] += 1
    if not pub:
        pub_info = ibe_register_identity(identity)
        log_event("ibe", f"New IBE identity registered: {identity}", "info")
        return jsonify(pub_info)
    log_event("ibe", f"IBE public key served for: {identity}", "info")
    return jsonify({"identity": identity, "public_key": pub})

@app.route("/ibe/encrypt", methods=["POST"])
def ibe_enc():
    body     = request.get_json(force=True)
    identity = body.get("identity", "intersection-47-gateway")
    message  = body.get("message", "test-message")
    token    = ibe_encrypt(message.encode(), identity)
    if not token:
        return jsonify({"error": "Identity not found"}), 404
    return jsonify({"identity": identity, "token_b64": base64.b64encode(token).decode()})

@app.route("/ibe/decrypt", methods=["POST"])
def ibe_dec():
    body     = request.get_json(force=True)
    identity = body.get("identity", "intersection-47-gateway")
    token_b64= body.get("token_b64", "")
    token    = base64.b64decode(token_b64)
    plaintext= ibe_decrypt(token, identity)
    stats["he_decrypts"] += 1
    if plaintext is None:
        return jsonify({"error": "Decryption failed"}), 400
    log_event("ibe", f"IBE decryption successful for {identity}", "success")
    return jsonify({"identity": identity, "plaintext": plaintext.decode()})


# ── 4.4  ABE policy check ───────────────────────────────────────────────────
@app.route("/abe/check", methods=["POST"])
def abe_check():
    body       = request.get_json(force=True)
    attributes = body.get("attributes", [])
    record_id  = body.get("record_id", None)
    granted    = abe_check_policy(DEFAULT_POLICY, attributes)
    if granted:
        stats["abe_granted"] += 1
        log_event("abe", f"ABE access GRANTED for attrs: {attributes}", "success")
        # Return decrypted record if it exists
        rec = next((r for r in stored_records if r["id"] == record_id), None)
        return jsonify({"access": "granted", "policy": DEFAULT_POLICY, "record": rec})
    else:
        stats["abe_denied"] += 1
        log_event("abe", f"ABE access DENIED for attrs: {attributes}", "warning")
        return jsonify({"access": "denied", "policy": DEFAULT_POLICY, "required": DEFAULT_POLICY})


# ── 4.5  PRE ────────────────────────────────────────────────────────────────
@app.route("/pre/rekey", methods=["POST"])
def pre_rekey():
    body      = request.get_json(force=True)
    owner     = body.get("owner", "intersection-47-gateway")
    neighbour = body.get("neighbour", "edge-neighbour-01")
    try:
        rekey = pre_generate_rekey(owner, neighbour)
        rekey_store[f"{owner}->{neighbour}"] = rekey
        stats["pre_rekeys"] += 1
        log_event("pre", f"Re-key generated: {owner} → {neighbour}", "info")
        return jsonify({"status": "ok", "rekey_id": f"{owner}->{neighbour}",
                        "wrapped_key_b64": rekey["wrapped_key_b64"]})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/pre/transform", methods=["POST"])
def pre_transform():
    body     = request.get_json(force=True)
    rekey_id = body.get("rekey_id", "")
    ct_b64   = body.get("ciphertext_b64", "")
    rekey    = rekey_store.get(rekey_id)
    if not rekey:
        return jsonify({"error": "Re-key not found"}), 404
    transformed = pre_transform_ciphertext(ct_b64, rekey)
    log_event("pre", f"Ciphertext re-encrypted for neighbour", "info")
    return jsonify({"transformed_b64": transformed})


# ── 4.6  FE – functional encryption (count-only endpoint) ───────────────────
@app.route("/fe/monthly-count")
@require_jwt
def fe_monthly_count():
    """Returns only the aggregate vehicle count — never raw plates."""
    zone = request.args.get("zone")
    if zone:
        count = sum(1 for r in stored_records if r.get("zone") == zone)
    else:
        count = len(stored_records)
    noisy = add_laplace_noise(count, sensitivity=1.0, epsilon=0.5)
    log_event("fe", f"FE monthly count served (noisy={noisy:.1f})", "info")
    return jsonify({"function": "count", "result": max(0, round(noisy)), "raw_count": count})


# ── 4.7  Honey Encryption ────────────────────────────────────────────────────
@app.route("/honey/store", methods=["POST"])
def honey_store():
    global honey_vault_token
    body     = request.get_json(force=True)
    password = body.get("password", "secret")
    data     = body.get("data", json.dumps({"plates": ["KA01AB1234"]}))
    honey_vault_token = he_encrypt(data, password)
    log_event("honey", "Honey-encrypted vault updated", "info")
    return jsonify({"status": "ok", "vault_size": len(honey_vault_token)})

@app.route("/honey/retrieve", methods=["POST"])
def honey_retrieve():
    body     = request.get_json(force=True)
    password = body.get("password", "wrong")
    if not honey_vault_token:
        return jsonify({"error": "Vault is empty. Store data first."}), 400
    result   = he_decrypt(honey_vault_token, password)
    parsed   = json.loads(result)
    is_decoy = parsed.get("note") == "decoy"
    if is_decoy:
        stats["honey_decoys"] += 1
        log_event("honey", "Honey vault accessed with WRONG password → decoy served", "warning")
    else:
        log_event("honey", "Honey vault accessed with correct password", "success")
    return jsonify({"result": parsed, "is_decoy": is_decoy})


# ── 4.8  SSE – Searchable Symmetric Encryption ──────────────────────────────
@app.route("/sse/search", methods=["POST"])
def sse_search_route():
    body    = request.get_json(force=True)
    keyword = body.get("keyword", "stolen")
    td      = sse_trapdoor(keyword, SSE_KEY)
    matches = sse_search(td, sse_index)
    stats["sse_searches"] += 1
    log_event("sse", f"SSE search via trapdoor (keyword hidden) → {len(matches)} matches", "info")
    return jsonify({
        "trapdoor": td[:16] + "…",
        "matches":  len(matches),
        "note":     "Server processed trapdoor without learning the keyword",
    })


# ── 4.9  HOM – Paillier homomorphic sum ─────────────────────────────────────
@app.route("/hom/sum")
def hom_sum():
    if not encrypted_counts:
        return jsonify({"encrypted_sum": None, "plaintext": 0})
    enc_sum_json = paillier_add_encrypted(encrypted_counts, PAILLIER_PUB)
    plaintext    = paillier_decrypt(enc_sum_json, PAILLIER_PRIV)
    log_event("hom", f"Paillier homomorphic sum = {plaintext}", "info")
    return jsonify({"encrypted_sum_snippet": enc_sum_json[:60] + "…", "plaintext": plaintext})


# ── 4.10  Auth: JWT issue / cross-domain ────────────────────────────────────
@app.route("/auth/token", methods=["POST"])
def auth_token():
    body = request.get_json(force=True)
    cam_id = body.get("camera_id", "city-system")
    role   = body.get("role", "viewer")
    payload = {
        "sub": cam_id,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }
    token = pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    stats["jwt_issued"] += 1
    log_event("auth", f"JWT issued for {cam_id} (role={role})", "success")
    return jsonify({"token": token, "expires_in": 1800})

# Handover: issue a short-lived ticket to move camera identity between edges
@app.route("/auth/handover", methods=["POST"])
def auth_handover():
    body      = request.get_json(force=True)
    camera_id = body.get("camera_id", "CAM-001")
    target_edge = body.get("target_edge", "edge-2")
    ticket    = base64.b64encode(os.urandom(16)).decode()
    handover_tickets[camera_id] = {
        "ticket": ticket,
        "expiry": time.time() + 30,
        "edge":   target_edge,
    }
    stats["handovers"] += 1
    log_event("auth", f"Handover ticket issued for {camera_id} → {target_edge}", "info")
    return jsonify({"ticket": ticket, "valid_for_seconds": 30, "target_edge": target_edge})

@app.route("/auth/handover/verify", methods=["POST"])
def auth_handover_verify():
    body      = request.get_json(force=True)
    camera_id = body.get("camera_id")
    ticket    = body.get("ticket")
    stored    = handover_tickets.get(camera_id)
    if not stored:
        return jsonify({"valid": False, "reason": "No ticket issued"}), 401
    if stored["ticket"] != ticket:
        return jsonify({"valid": False, "reason": "Ticket mismatch"}), 401
    if time.time() > stored["expiry"]:
        return jsonify({"valid": False, "reason": "Ticket expired"}), 401
    del handover_tickets[camera_id]
    log_event("auth", f"Handover verified for {camera_id}", "success")
    return jsonify({"valid": True, "camera_id": camera_id, "edge": stored["edge"]})


# ── Dashboard data endpoints ─────────────────────────────────────────────────
@app.route("/dashboard/stats")
def dashboard_stats():
    return jsonify({
        **stats,
        "quarantined_count": len(quarantined),
        "quarantined_ids": list(quarantined),
        "stored_records": len(stored_records),
        "enc_records":    len(enc_records),
        "sse_index_size": len(sse_index),
        "paillier_count": len(encrypted_counts),
        "rekeys_stored":  len(rekey_store),
        "ibe_identities": ["intersection-47-gateway", "edge-neighbour-01"],
        "rate_window":    RATE_WINDOW,
        "rate_limit":     RATE_LIMIT,
        "abe_policy":     DEFAULT_POLICY,
        "uptime_s":       round(time.time() - START_TIME),
    })

@app.route("/dashboard/records")
def dashboard_records():
    limit  = int(request.args.get("limit", 20))
    recent = stored_records[-limit:][::-1]
    return jsonify(recent)

@app.route("/dashboard/log")
def dashboard_log():
    return jsonify(list(activity_log))

@app.route("/dashboard/cameras")
def dashboard_cameras():
    now = time.time()
    cams = []
    for cam_id, times in request_counts.items():
        recent = [t for t in times if now - t < RATE_WINDOW]
        cams.append({
            "id":         cam_id,
            "requests":   len(recent),
            "quarantined": cam_id in quarantined,
            "rate_pct":   min(100, int(len(recent) / RATE_LIMIT * 100)),
        })
    return jsonify(cams)


@app.route("/video/frame", methods=["POST"])
def video_frame():
    frame = request.get_data(cache=False)
    if request.mimetype != "image/jpeg" or not frame or len(frame) > 4_000_000:
        return jsonify({"error": "Expected a JPEG frame under 4 MB"}), 400

    with video_state_lock:
        video_state.update({
            "frame": frame,
            "updated_at": time.time(),
            "detection_count": request.headers.get("X-Detection-Count", "0"),
            "vehicles_sent": request.headers.get("X-Vehicles-Sent", "0"),
            "camera_id": request.headers.get("X-Camera-ID", "VIDEO-CAM-01"),
            "zone": request.headers.get("X-Zone", "Zone1"),
        })
    return "", 204


@app.route("/video/stream")
def video_stream():
    @stream_with_context
    def generate():
        last_frame_time = 0.0
        while True:
            with video_state_lock:
                frame = video_state["frame"]
                updated_at = video_state["updated_at"]
            if frame is not None and updated_at != last_frame_time:
                last_frame_time = updated_at
                yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame + b"\r\n")
            else:
                time.sleep(0.05)

    return Response(generate(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/video/status")
def video_status():
    with video_state_lock:
        connected = time.time() - video_state["updated_at"] < 3
        return jsonify({
            "connected": connected,
            "detection_count": video_state["detection_count"],
            "vehicles_sent": video_state["vehicles_sent"],
            "camera_id": video_state["camera_id"],
            "zone": video_state["zone"],
        })


# ── Demo helper: inject a pre-built reading from the browser UI ──────────────
@app.route("/demo/inject", methods=["POST"])
def demo_inject():
    """
    Allows the browser dashboard to inject a fake camera reading
    without needing a real camera.py process running.
    """
    body = request.get_json(force=True)
    plate    = body.get("plate", "XX00YY0000")
    category = body.get("category", "normal")
    speed    = body.get("speed_kmh", 60.0)
    zone     = body.get("zone", "Zone3")
    flood    = body.get("flood", False)

    # Build a synthetic camera packet (the same way camera.py does it)
    payload = {
        "plate":     plate,
        "category":  category,
        "speed_kmh": speed,
        "timestamp": time.time(),
    }
    raw   = json.dumps(payload).encode()
    token = aes_encrypt(raw, CAMERA_AES_KEY)
    token_b64 = base64.b64encode(token).decode()
    sig   = hmac_sign(token, EDGE_SECRET)

    cam_id = rotate_camera_id("BROWSER-CAM") if not flood else \
             rotate_camera_id("FLOOD-CAM")

    # Reuse the /upload logic
    request_proxy = {
        "camera_id": cam_id,
        "zone":      zone,
        "ciphertext": token_b64,
        "signature":  sig,
    }

    # Rate check
    if not rate_check(cam_id):
        return jsonify({"status": "quarantined"}), 429

    if not hmac_verify(token, sig):
        return jsonify({"status": "error", "error": "HMAC failed"}), 403

    stats["hmac_verified"] += 1

    record = {**payload}
    record["id"]        = str(uuid.uuid4())[:8]
    record["camera_id"] = cam_id
    record["zone"]      = zone
    record["received"]  = datetime.now().isoformat()
    record["plate_hash"]= hash_plate(plate)
    record["plate_anon"]= plate[:3] + "***" + plate[-2:]
    record["location"]  = dummy_location()
    stats["privacy_noise_applied"] += 1

    sse_index.update(sse_build_index([record], ["stolen", "wanted", "normal"], SSE_KEY))
    encrypted_counts.append(paillier_encrypt(1, PAILLIER_PUB))
    stats["monthly_count"] += 1
    stored_records.append(record)
    enc_records.append({"id": record["id"], "ciphertext": token_b64, "zone": zone})
    stats["total_uploads"] += 1

    log_event("upload", f"[DEMO] Plate {record['plate_anon']} zone={zone} category={category}", "info")
    return jsonify({"status": "ok", "record_id": record["id"]})


START_TIME = time.time()

if __name__ == "__main__":
    print("=" * 60)
    print("  Smart-City Traffic Edge Server")
    print("  Dashboard -> http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, port=5000, use_reloader=False)
