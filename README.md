# Smart-City Traffic Camera Edge Box

This project simulates a traffic-camera edge node that handles synthetic vehicle readings without using real number-plate data. It includes a Python camera simulator, a Flask edge server, a browser dashboard and an optional video-based motion-detection input.

The security features are educational demonstrations. They are not a production-ready traffic surveillance or cryptographic platform.

## Requirements

- Python 3.10 or later
- Windows, macOS or Linux

## Setup

From the project directory, create and activate a virtual environment if desired, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create a local `.env` file and configure separate random secrets. The `.env` file is ignored by Git:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Run the command twice and use the two different values to replace the `EDGE_SECRET` and `JWT_SECRET` placeholders in `.env`. Keep this file private and do not commit it.

## Run the edge dashboard

```powershell
python edge_server.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in a browser.

## Run a simulated camera

In another terminal opened in the project directory:

```powershell
python camera.py --camera-id CAM-001 --zone Zone3
```

To exercise rate-limit detection:

```powershell
python camera.py --camera-id CAM-FLOOD --flood
```

The camera and server load the same `.env` secrets. The server must be running first.

## Optional video input

Use your own road-traffic video file; video files are excluded from this public repository.

```powershell
python video_camera.py --video path\to\your-video.mp4
```

This mode uses OpenCV background subtraction to detect moving regions and generates synthetic plate metadata. It does not perform optical number-plate recognition, and its speed estimate is illustrative.

## Demonstrated components

- AES-128-CBC encryption and HMAC-SHA256 validation for camera packets
- Simulated IBE identity keys, an attribute-policy checker and a simplified PRE workflow
- JWT-protected noisy aggregate queries, a Honey-style decoy vault and SSE keyword trapdoors
- Paillier encrypted count addition, camera ID rotation, hashed/masked plate display and dummy locations
- Rate limiting and a browser dashboard for records, counters and activity events

Several items above are simplified demonstrations rather than full implementations of the named cryptographic schemes. The local server uses HTTP, keeps runtime data in memory and is intended for educational use only.

## Report and implementation

See [IMPLEMENTATION_REPORT.md](./IMPLEMENTATION_REPORT.md) for the implementation summary, functional checks, observations and screenshot placeholders.
