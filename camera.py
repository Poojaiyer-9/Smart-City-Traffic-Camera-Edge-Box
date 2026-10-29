"""
camera.py  –  Simulated Traffic Camera (Sensor / Resource-Constrained Device)
==============================================================================
Deliberately restricted to AES + HMAC only (4.13 resource-constrained device).

Covers implemented topics:
  4.1  CIA       – AES encrypt + HMAC sign every reading
  4.10 Auth      – pre-shared HMAC key (single-domain)
  4.11 Privacy   – temporary camera ID rotation
  4.13 Resource  – lightweight: no PKI, no asymmetric ops
"""

import os
import sys
import time
import json
import random
import string
import hashlib
import base64
import requests
import argparse
import threading

from crypto_utils import (
    aes_encrypt,
    hmac_sign,
    rotate_camera_id,
    EDGE_SECRET,
    AES_KEY_LEN,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
EDGE_URL    = os.getenv("EDGE_URL", "http://127.0.0.1:5000")
CAMERA_ID   = os.getenv("CAMERA_ID", f"CAM-{os.urandom(3).hex().upper()}")
ZONE        = os.getenv("CAMERA_ZONE", "Zone3")
INTERVAL    = float(os.getenv("SEND_INTERVAL", "2.5"))   # seconds between readings

# AES key shared with edge server (pre-provisioned)
CAMERA_AES_KEY = hashlib.sha256(EDGE_SECRET).digest()[:AES_KEY_LEN]

# ---------------------------------------------------------------------------
# Plate generation
# ---------------------------------------------------------------------------
STATE_CODES  = ["KA", "MH", "DL", "TN", "AP", "GJ", "RJ", "UP", "WB", "HR"]
CATEGORIES   = ["stolen", "wanted", "normal", "normal", "normal", "normal"]  # weighted

def generate_plate() -> dict:
    """Generate a realistic-looking fake number plate with metadata."""
    state = random.choice(STATE_CODES)
    dist  = str(random.randint(1, 99)).zfill(2)
    alpha = "".join(random.choices(string.ascii_uppercase, k=2))
    num   = str(random.randint(1000, 9999))
    plate = f"{state}{dist}{alpha}{num}"
    return {
        "plate": plate,
        "category": random.choice(CATEGORIES),
        "speed_kmh": round(random.uniform(20, 120), 1),
        "timestamp": time.time(),
    }


# ---------------------------------------------------------------------------
# Core send loop
# ---------------------------------------------------------------------------

def encrypt_and_sign(payload: dict) -> dict:
    """
    AES-encrypt the payload JSON.
    Attach HMAC-SHA256 signature (pre-shared key, single-domain auth).
    Rotate camera ID for privacy.
    """
    raw   = json.dumps(payload).encode()
    token = aes_encrypt(raw, CAMERA_AES_KEY)
    token_b64 = base64.b64encode(token).decode()
    sig   = hmac_sign(token, EDGE_SECRET)

    # Rotate pseudo-ID every 10 minutes (4.11 privacy)
    pseudo_id = rotate_camera_id(CAMERA_ID)

    return {
        "camera_id": pseudo_id,
        "zone": ZONE,
        "ciphertext": token_b64,
        "signature": sig,
    }


def send_reading(session: requests.Session, flood: bool = False) -> None:
    """Generate one plate reading, encrypt it, and POST to the edge server."""
    payload = generate_plate()
    packet  = encrypt_and_sign(payload)
    try:
        resp = session.post(f"{EDGE_URL}/upload", json=packet, timeout=5)
        if resp.status_code == 200:
            print(f"[{CAMERA_ID}] Sent plate (pseudo={packet['camera_id'][-8:]})"
                  f" → {resp.json().get('status', '?')}")
        elif resp.status_code == 429:
            print(f"[{CAMERA_ID}] *** QUARANTINED (rate-limited) ***")
        else:
            print(f"[{CAMERA_ID}] Server replied {resp.status_code}: {resp.text[:80]}")
    except requests.RequestException as exc:
        print(f"[{CAMERA_ID}] Connection error: {exc}")


def flood_attack(session: requests.Session, burst: int = 50) -> None:
    """Simulate a DoS flood to trigger attack detection on the edge."""
    print(f"[{CAMERA_ID}] ⚠  Starting flood attack ({burst} requests) …")
    for _ in range(burst):
        send_reading(session, flood=True)
        time.sleep(0.05)   # very fast


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global EDGE_URL, CAMERA_ID, ZONE, INTERVAL   # declare before any use

    parser = argparse.ArgumentParser(description="Smart-City Traffic Camera Simulator")
    parser.add_argument("--flood",    action="store_true", help="Trigger flood attack")
    parser.add_argument("--interval", type=float, default=INTERVAL)
    parser.add_argument("--edge-url", default=EDGE_URL)
    parser.add_argument("--camera-id", default=CAMERA_ID)
    parser.add_argument("--zone", default=ZONE)
    args = parser.parse_args()

    EDGE_URL  = args.edge_url
    CAMERA_ID = args.camera_id
    ZONE      = args.zone
    INTERVAL  = args.interval

    print(f"[Camera] Starting — ID={CAMERA_ID}  Zone={ZONE}  Edge={EDGE_URL}")
    session = requests.Session()

    if args.flood:
        flood_attack(session)
        return

    try:
        while True:
            send_reading(session)
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print(f"\n[{CAMERA_ID}] Stopped.")


if __name__ == "__main__":
    main()
