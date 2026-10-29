"""
video_camera.py  –  Road Transport Video Simulator
====================================================
Drop any highway / road traffic video in this folder, then run:

    python video_camera.py --video road.mp4

What it does:
  1. Reads video frame-by-frame with OpenCV
  2. Detects moving vehicles using background subtraction
  3. For each detected vehicle generates a realistic plate + metadata
  4. AES-encrypts + HMAC-signs the packet  (same as camera.py)
  5. POSTs to edge_server.py  /upload endpoint
  6. Shows a live annotated window with bounding boxes + stats

Security features exercised (same as camera.py):
  4.1  CIA       – AES encrypt + HMAC sign every reading
  4.10 Auth      – pre-shared HMAC key
  4.11 Privacy   – camera ID rotation
  4.13 Resource  – lightweight: no PKI, no asymmetric ops
"""

import os
import sys
import cv2
import time
import json
import math
import random
import string
import hashlib
import base64
import argparse
import threading
import requests
from datetime import datetime
from collections import deque

from crypto_utils import (
    aes_encrypt,
    hmac_sign,
    rotate_camera_id,
    EDGE_SECRET,
    AES_KEY_LEN,
)

# ── Configuration ────────────────────────────────────────────────────────────
EDGE_URL        = os.getenv("EDGE_URL", "http://127.0.0.1:5000")
CAMERA_ID       = os.getenv("CAMERA_ID", "VIDEO-CAM-01")
ZONE            = os.getenv("CAMERA_ZONE", "Zone1")
CAMERA_AES_KEY  = hashlib.sha256(EDGE_SECRET).digest()[:AES_KEY_LEN]

# ── Plate generation helpers ──────────────────────────────────────────────────
STATE_CODES = ["KA", "MH", "DL", "TN", "AP", "GJ", "RJ", "UP", "WB", "HR",
               "PB", "MP", "BR", "OD", "JH"]
CATEGORIES  = ["stolen", "wanted", "normal", "normal", "normal", "normal",
               "normal", "normal"]   # weighted toward normal

# Roughly one "special" vehicle every N detections
_plate_counter = 0

def generate_plate(vehicle_width_px: int, vehicle_height_px: int,
                   speed_kmh: float) -> dict:
    """
    Generate a realistic-looking fake plate with metadata derived from the
    actual video frame (size → vehicle type, speed estimate).
    """
    global _plate_counter
    _plate_counter += 1

    state  = random.choice(STATE_CODES)
    dist   = str(random.randint(1, 99)).zfill(2)
    alpha  = "".join(random.choices(string.ascii_uppercase, k=2))
    num    = str(random.randint(1000, 9999))
    plate  = f"{state}{dist}{alpha}{num}"

    # Derive vehicle type from bounding-box size
    area = vehicle_width_px * vehicle_height_px
    if area > 60_000:
        vehicle_type = "truck"
    elif area > 25_000:
        vehicle_type = "bus"
    elif area > 8_000:
        vehicle_type = "car"
    else:
        vehicle_type = "bike"

    # Bias category: every ~20th detection force stolen/wanted
    if _plate_counter % 20 == 0:
        category = random.choice(["stolen", "wanted"])
    else:
        category = random.choice(CATEGORIES)

    return {
        "plate":        plate,
        "category":     category,
        "vehicle_type": vehicle_type,
        "speed_kmh":    round(speed_kmh, 1),
        "timestamp":    time.time(),
    }


# ── Encrypt + sign ────────────────────────────────────────────────────────────
def encrypt_and_sign(payload: dict, camera_id: str, zone: str) -> dict:
    raw       = json.dumps(payload).encode()
    token     = aes_encrypt(raw, CAMERA_AES_KEY)
    token_b64 = base64.b64encode(token).decode()
    sig       = hmac_sign(token, EDGE_SECRET)
    pseudo_id = rotate_camera_id(camera_id)
    return {
        "camera_id":  pseudo_id,
        "zone":       zone,
        "ciphertext": token_b64,
        "signature":  sig,
    }


# ── Send to edge (non-blocking thread) ───────────────────────────────────────
_send_results: deque = deque(maxlen=50)

def _post(session: requests.Session, packet: dict, plate: str,
          vehicle_type: str, category: str):
    try:
        r = session.post(f"{EDGE_URL}/upload", json=packet, timeout=4)
        status = r.json().get("status", "?") if r.status_code == 200 else f"HTTP {r.status_code}"
    except Exception as exc:
        status = f"ERR: {exc}"
    _send_results.appendleft({
        "time":     datetime.now().strftime("%H:%M:%S"),
        "plate":    plate[:3] + "***" + plate[-2:],
        "type":     vehicle_type,
        "category": category,
        "status":   status,
    })


def send_async(session: requests.Session, packet: dict, plate: str,
               vehicle_type: str, category: str):
    t = threading.Thread(target=_post,
                         args=(session, packet, plate, vehicle_type, category),
                         daemon=True)
    t.start()


# ── Vehicle detector (background subtraction) ────────────────────────────────
class VehicleDetector:
    """
    Uses MOG2 background subtraction to isolate moving objects.
    Merges overlapping contours and filters by area.
    """

    MIN_AREA   = 2_500    # px² – ignore tiny blobs (noise)
    MAX_AREA   = 200_000  # px² – ignore full-frame blobs
    MERGE_DIST = 60       # px  – merge nearby bounding boxes

    def __init__(self):
        self.bg = cv2.createBackgroundSubtractorMOG2(
            history=300, varThreshold=50, detectShadows=False
        )
        # simple speed estimator: centroid tracks
        self._prev_centroids: list = []

    def detect(self, frame):
        """
        Returns list of (x, y, w, h, speed_kmh) for each detected vehicle.
        """
        gray   = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        blur   = cv2.GaussianBlur(gray, (5, 5), 0)
        mask   = self.bg.apply(blur)

        # morphological cleanup
        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
        mask   = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel, iterations=2)
        mask   = cv2.morphologyEx(mask, cv2.MORPH_OPEN,  kernel, iterations=1)
        mask   = cv2.dilate(mask, kernel, iterations=2)

        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL,
                                        cv2.CHAIN_APPROX_SIMPLE)

        boxes = []
        for c in contours:
            area = cv2.contourArea(c)
            if self.MIN_AREA < area < self.MAX_AREA:
                boxes.append(cv2.boundingRect(c))

        merged   = self._merge_boxes(boxes)
        current_centroids = [(x + w//2, y + h//2) for x, y, w, h in merged]

        results = []
        for i, (x, y, w, h) in enumerate(merged):
            cx, cy = current_centroids[i]
            speed  = self._estimate_speed(cx, cy)
            results.append((x, y, w, h, speed))

        self._prev_centroids = current_centroids
        return results

    def _merge_boxes(self, boxes):
        """Merge bounding boxes that are close to each other."""
        if not boxes:
            return []
        rects  = [list(b) for b in boxes]
        merged = True
        while merged:
            merged = False
            result = []
            used   = [False] * len(rects)
            for i in range(len(rects)):
                if used[i]:
                    continue
                x1, y1, w1, h1 = rects[i]
                for j in range(i + 1, len(rects)):
                    if used[j]:
                        continue
                    x2, y2, w2, h2 = rects[j]
                    # centre-to-centre distance
                    dist = math.hypot((x1 + w1//2) - (x2 + w2//2),
                                      (y1 + h1//2) - (y2 + h2//2))
                    if dist < self.MERGE_DIST:
                        nx = min(x1, x2)
                        ny = min(y1, y2)
                        nw = max(x1+w1, x2+w2) - nx
                        nh = max(y1+h1, y2+h2) - ny
                        rects[i] = [nx, ny, nw, nh]
                        x1, y1, w1, h1 = rects[i]
                        used[j] = True
                        merged  = True
                result.append(tuple(rects[i]))
                used[i] = True
            rects = result
        return rects

    def _estimate_speed(self, cx, cy) -> float:
        """
        Very rough pixel-displacement speed estimate in km/h.
        (Calibration is illustrative — not physically accurate without
        real camera parameters.)
        """
        if not self._prev_centroids:
            return random.uniform(30, 90)
        # find nearest previous centroid
        dists = [math.hypot(cx - px, cy - py)
                 for px, py in self._prev_centroids]
        disp  = min(dists)
        # ~0.05 m/px * 30 fps → m/s → km/h  (rough)
        speed = disp * 0.05 * 30 * 3.6
        return min(max(speed, 10.0), 140.0)


# ── HUD overlay ──────────────────────────────────────────────────────────────
def draw_hud(frame, detections, total_sent, zone, fps_actual):
    h, w = frame.shape[:2]

    # Semi-transparent top bar
    overlay = frame.copy()
    cv2.rectangle(overlay, (0, 0), (w, 44), (20, 20, 20), -1)
    cv2.addWeighted(overlay, 0.65, frame, 0.35, 0, frame)

    # Top info
    ts  = datetime.now().strftime("%H:%M:%S")
    cv2.putText(frame,
                f"  EDGE AI Traffic Monitor | Zone: {zone} | Vehicles sent: {total_sent}"
                f"  |  FPS: {fps_actual:.1f}  |  {ts}",
                (6, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.52, (0, 230, 255), 1, cv2.LINE_AA)

    # Vehicle bounding boxes
    CAT_COLORS = {
        "normal": (0, 220, 80),
        "stolen": (0, 0, 255),
        "wanted": (0, 140, 255),
    }
    for (x, y, bw, bh, speed) in detections:
        color = (0, 200, 255)   # default cyan (pre-send, category unknown)
        cv2.rectangle(frame, (x, y), (x+bw, y+bh), color, 2)
        label = f"{speed:.0f} km/h"
        (lw, lh), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.45, 1)
        cv2.rectangle(frame, (x, y-lh-6), (x+lw+4, y), (20, 20, 20), -1)
        cv2.putText(frame, label, (x+2, y-4),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1, cv2.LINE_AA)

    # Right panel – last 6 sends
    panel_x = w - 310
    recent_results = list(_send_results)[:6]
    overlay2 = frame.copy()
    cv2.rectangle(overlay2, (panel_x - 6, 50), (w - 2, 50 + 30 + len(recent_results)*20),
                  (15, 15, 15), -1)
    cv2.addWeighted(overlay2, 0.7, frame, 0.3, 0, frame)

    cv2.putText(frame, "Recent Detections:", (panel_x, 68),
                cv2.FONT_HERSHEY_SIMPLEX, 0.45, (200, 200, 200), 1)
    for i, rec in enumerate(recent_results):
        cat    = rec["category"]
        color  = CAT_COLORS.get(cat, (180, 180, 180))
        text   = f"{rec['time']}  {rec['plate']}  {rec['type'][:3]}  {cat[:3].upper()}"
        cv2.putText(frame, text, (panel_x, 86 + i * 20),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.38, color, 1, cv2.LINE_AA)

    return frame


# ── Main loop ────────────────────────────────────────────────────────────────
def run(video_path: str, camera_id: str, zone: str, edge_url: str,
        cooldown: float, show: bool, scale: float):
    """
    Main video processing loop.

    Args:
        video_path  : path to .mp4 / .avi / .mkv file
        camera_id   : logical camera name
        zone        : traffic zone label
        edge_url    : edge server base URL
        cooldown    : min seconds between uploads per vehicle
        show        : whether to display the OpenCV window
        scale       : resize factor for display (0.5 = half size)
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print(f"[ERROR] Cannot open video: {video_path}")
        sys.exit(1)

    fps_video   = cap.get(cv2.CAP_PROP_FPS) or 25
    total_frames= int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration_s  = total_frames / fps_video

    print("=" * 62)
    print(f"  Video    : {os.path.basename(video_path)}")
    print(f"  Camera   : {camera_id}  Zone: {zone}")
    print(f"  Frames   : {total_frames}  FPS: {fps_video:.1f}  Duration: {duration_s:.1f}s")
    print(f"  Edge URL : {edge_url}")
    print(f"  Cooldown : {cooldown}s per vehicle")
    print(f"  Window   : {'ON' if show else 'OFF (headless)'}")
    print("=" * 62)
    print("Press  Q  in the video window to quit.\n")

    detector     = VehicleDetector()
    session      = requests.Session()
    total_sent   = 0
    last_sent_ts = 0.0      # cooldown to avoid spamming server
    frame_idx    = 0
    last_frame_post_ts = 0.0
    frame_session = requests.Session()

    # FPS tracking
    fps_buf    = deque(maxlen=30)
    t_prev     = time.time()
    playback_start = time.perf_counter()

    while True:
        ret, frame = cap.read()
        if not ret:
            print(f"\n[INFO] End of video after {frame_idx} frames, {total_sent} vehicles sent.")
            break

        frame_idx += 1
        target_time = playback_start + frame_idx / fps_video
        time.sleep(max(0, target_time - time.perf_counter()))
        t_now = time.time()
        fps_buf.append(1.0 / max(t_now - t_prev, 1e-6))
        t_prev = t_now
        fps_actual = sum(fps_buf) / len(fps_buf)

        # Skip frames to keep processing fast (process every 2nd frame)
        if frame_idx % 2 != 0:
            continue

        detections = detector.detect(frame)

        # If vehicles detected and cooldown elapsed → send ONE packet
        if detections and (t_now - last_sent_ts) >= cooldown:
            # Pick the largest detection (most prominent vehicle)
            x, y, bw, bh, speed = max(detections, key=lambda d: d[2]*d[3])
            payload = generate_plate(bw, bh, speed)
            packet  = encrypt_and_sign(payload, camera_id, zone)

            send_async(session, packet,
                       payload["plate"], payload["vehicle_type"], payload["category"])
            total_sent   += 1
            last_sent_ts  = t_now

            cat  = payload["category"]
            icon = "(!)" if cat in ("stolen", "wanted") else ">>>"
            print(f"[{camera_id}] Frame {frame_idx:5d} | {icon} {payload['plate']}"
                  f"  {payload['vehicle_type']:5s}  {payload['speed_kmh']} km/h"
                  f"  [{cat}]  -> sent #{total_sent}")

        display = draw_hud(frame.copy(), detections, total_sent, zone, fps_actual)
        if t_now - last_frame_post_ts >= 0.1:
            encoded_ok, encoded_frame = cv2.imencode(
                ".jpg", display, [cv2.IMWRITE_JPEG_QUALITY, 75]
            )
            if encoded_ok:
                try:
                    frame_session.post(
                        f"{edge_url}/video/frame",
                        data=encoded_frame.tobytes(),
                        headers={
                            "Content-Type": "image/jpeg",
                            "X-Detection-Count": str(len(detections)),
                            "X-Vehicles-Sent": str(total_sent),
                            "X-Camera-ID": camera_id,
                            "X-Zone": zone,
                        },
                        timeout=0.5,
                    )
                except requests.RequestException:
                    pass
            last_frame_post_ts = t_now

        if show:
            if scale != 1.0:
                dh, dw = display.shape[:2]
                display = cv2.resize(display,
                                     (int(dw * scale), int(dh * scale)))
            cv2.imshow("Edge AI Traffic Monitor", display)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                print("\n[INFO] User quit.")
                break

    cap.release()
    if show:
        cv2.destroyAllWindows()
    print(f"\n[DONE] Total vehicles sent to edge server: {total_sent}")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Road Transport Video Simulator for Smart-City Edge AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python video_camera.py --video road.mp4
  python video_camera.py --video highway.mp4 --zone Zone2 --cooldown 1.5
  python video_camera.py --video traffic.mp4 --no-window   (headless / server mode)
  python video_camera.py --video clip.mp4 --scale 0.6      (smaller window)
""",
    )
    parser.add_argument("--video",      required=True,
                        help="Path to road/highway video file (.mp4 .avi .mkv)")
    parser.add_argument("--camera-id",  default=CAMERA_ID,
                        help="Logical camera ID (default: VIDEO-CAM-01)")
    parser.add_argument("--zone",       default=ZONE,
                        help="Traffic zone label (default: Zone1)")
    parser.add_argument("--edge-url",   default=EDGE_URL,
                        help="Edge server URL (default: http://127.0.0.1:5000)")
    parser.add_argument("--cooldown",   type=float, default=2.0,
                        help="Min seconds between uploads (default: 2.0)")
    parser.add_argument("--no-window",  action="store_true",
                        help="Run headless (no OpenCV display window)")
    parser.add_argument("--scale",      type=float, default=0.75,
                        help="Display window scale factor (default: 0.75)")
    args = parser.parse_args()

    if not os.path.isfile(args.video):
        print(f"[ERROR] Video file not found: {args.video}")
        print(f"  Put your video in: {os.getcwd()}")
        print(f"  Then run:  python video_camera.py --video <filename>")
        sys.exit(1)

    run(
        video_path = args.video,
        camera_id  = args.camera_id,
        zone       = args.zone,
        edge_url   = args.edge_url,
        cooldown   = args.cooldown,
        show       = not args.no_window,
        scale      = args.scale,
    )


if __name__ == "__main__":
    main()
