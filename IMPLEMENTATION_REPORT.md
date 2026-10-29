# Simulated Smart-City Traffic Camera Edge Box

## Implementation and Test Report

**Student:** [Your name]  
**Course / section:** [Course name and section]  
**Submission date:** [Date]  
**Project type:** Local smart-city traffic and edge-security simulation

## 1. Project overview

This project demonstrates how a traffic-camera edge node can receive and process synthetic vehicle readings without relying on real number-plate data. A Python camera simulator generates realistic-looking sample plates and sends them to a Flask edge server. A browser dashboard displays recent readings, system activity and security demonstrations.

The project also includes an optional video-driven camera. It detects moving objects in a road clip, draws bounding boxes and sends generated vehicle metadata and annotated frames to the edge server. The plate values are generated for the simulation; the video component does not perform optical number-plate recognition.

The aim is to make several security and privacy ideas visible in one local demonstration. These mechanisms are educational simulations, not a production-ready traffic surveillance or cryptographic platform.

## 2. Design and implementation

### Camera-to-edge data flow

The simulated camera creates a sample plate, category, speed and timestamp. It encrypts the JSON reading with AES-128-CBC, signs the encrypted bytes with HMAC-SHA256, and posts the packet to the Flask `/upload` endpoint. Camera identifiers are pseudonymised and rotate in ten-minute intervals.

The edge server checks the signature before decrypting the packet. It then prepares a dashboard record, masks the plate for display, calculates a plate hash, adds a dummy location, updates the searchable index and records an encrypted copy of the upload. The current implementation keeps its records and cryptographic demonstration state in process memory.

The dashboard provides live counters, a recent-reading table, an upload chart and an activity log. Its buttons can inject a synthetic reading and trigger the rate-limit demonstration without starting a separate camera process.

### Security and privacy demonstrations

| Area | How it is demonstrated |
|---|---|
| CIA / message integrity | AES-encrypted camera packets are checked with HMAC-SHA256 before processing. |
| Identity-based encryption (IBE) | Named demo identities, including `intersection-47-gateway`, are associated with generated ECC keys for an encrypt/decrypt round trip. |
| Attribute policy (ABE) | A policy checker grants access when both `TrafficOfficer` and `Zone3` attributes are present. This is a policy simulation, not a full CP-ABE cryptosystem. |
| Proxy re-encryption (PRE) | A simplified re-key and ciphertext transformation workflow demonstrates the idea of transferring access between edge identities. |
| Count-only analytics (FE-style demo) | A JWT-protected endpoint returns a noisy aggregate count. In the current demo it also returns `raw_count`, and the count covers the current process's records rather than a calendar month. |
| Honey-style decoy | The vault returns plausible sample plates when decryption with a wrong password fails. This is a decoy demonstration, not a formal Honey Encryption construction. |
| Searchable symmetric encryption (SSE) | HMAC-derived keyword trapdoors are used to look up encrypted record identifiers in an in-memory index. |
| Homomorphic aggregation | Paillier-encrypted count increments are added and the result is decrypted by the demo utility. |
| Authentication and handover | Camera uploads use a pre-shared HMAC key; the demo can issue HS256 JWTs and short-lived, single-use handover tickets. |
| Privacy | The server hashes and masks plate values, adds Laplace noise to aggregate counts, inserts dummy coordinates and uses temporary camera IDs. |
| Flood detection | A per-camera rate limiter allows up to 10 requests in a 10-second window before quarantining that camera identifier. |
| Video input | OpenCV background subtraction detects moving regions, estimates speed illustratively and streams annotated frames to the dashboard. |

## 3. Steps to run and reproduce the demonstration

1. Install the packages listed in `requirements.txt` with `pip install -r requirements.txt`.
2. Start the local Flask edge server with `python edge_server.py` (or `START_SERVER.bat`).
3. Open the dashboard at `http://127.0.0.1:5000`.
4. Generate test readings using the dashboard's **Inject Reading** control or run `python camera.py --camera-id CAM-001 --zone Zone3`.
5. Use the dashboard controls to explore the IBE, access-policy, PRE, count-query, decoy-vault, SSE, Paillier, JWT, handover and privacy demonstrations.
6. Trigger the flood demonstration and check the quarantine status and activity log.
7. Optionally run `python video_camera.py --video video.mp4` to demonstrate video-based motion detection and the live dashboard feed.

## 4. Verification results

The following checks were run against the Flask application using its test client:

| Check | Observed result |
|---|---|
| Dashboard synthetic reading | Accepted; HTTP 200. |
| Camera-format encrypted upload | Accepted; HTTP 200. |
| Incorrect but well-formed HMAC | Rejected; HTTP 403. |
| Attribute-policy evaluation | Required attributes granted access; missing attribute was denied. |
| IBE demonstration | Encryption/decryption round trip returned the original test message. |
| Wrong-password vault access | A decoy result was returned and marked as a decoy. |
| SSE keyword search | Returned a matching record for the seeded test data. |
| JWT-protected aggregate endpoint | Accepted the issued JWT; HTTP 200. |
| Paillier count sum | Returned 2 after two test readings had been recorded. |
| Flood simulation | Requests beyond the configured threshold were rejected with HTTP 429 and the camera was quarantined. |

These are functional checks of the local demonstration, not a performance benchmark or an independent security audit.

## 5. Screenshots and evidence

Add your own screenshots in the spaces below. Use screenshots from your actual run, and avoid including personal data or unrelated desktop content.

**Figure 1 — Main dashboard with the edge server running**  
[Paste screenshot here]

**Figure 2 — Recent synthetic readings and masked plate values**  
[Paste screenshot here]

**Figure 3 — Security demonstrations (for example, policy result, IBE, or JWT count query)**  
[Paste screenshot here]

**Figure 4 — Flood detection and quarantined camera indicator**  
[Paste screenshot here]

**Figure 5 — Video camera feed with motion-detection boxes (if demonstrated)**  
[Paste screenshot here]

**Figure 6 — Terminal showing the camera or video-camera process sending readings**  
[Paste screenshot here]

## 6. Observations and scope

The local dashboard and API make the data flow and security concepts easy to demonstrate. Synthetic inputs also make repeatable testing possible without collecting real vehicle identifiers. The video mode adds a visual edge-processing example, while the dashboard makes the server's response visible as events occur.

Several details should be kept in mind when interpreting the demonstration:

- The default server URL uses HTTP. Camera payloads receive application-level AES encryption and HMAC protection, but TLS is not configured for the local web connection.
- Runtime records, tickets, indexes and encrypted-count data are held in memory. The application does not currently provide durable encrypted database storage or a separate backup edge process.
- The server decrypts readings for processing and retains a decoded record in memory; the dashboard masks plate values, but masking the display is not the same as removing the original value from server memory.
- The IBE, ABE, PRE, FE-style and Honey-style features are simplified demonstrations. Their labels describe the concepts being illustrated, not production-grade implementations of those cryptographic schemes.
- The count endpoint currently includes `raw_count` as well as a noisy result, and its count is based on the running process rather than filtering records by month.
- The edge HMAC and JWT secrets are loaded from a local `.env` file, which is excluded from Git. The application rejects missing or short secrets at startup; use distinct random values for each secret.
- Both malformed and well-formed but incorrect HMAC signatures are rejected with HTTP 403.
- The video script detects moving regions and generates sample plate metadata; it does not read actual number plates from the footage. Its speed estimate is illustrative and is not calibrated for real traffic enforcement.

## 7. Conclusion

The Smart-City Traffic Camera Edge Box brings together a synthetic camera, a local edge API, a monitoring dashboard and interactive security demonstrations. The checks confirmed that the main demo workflows operate locally, including encrypted uploads, HMAC verification, access-policy decisions, aggregate queries, searchable-index lookups and rate-limit quarantine. The project is suitable as a learning prototype; additional transport security, key management, persistent storage, validation and availability engineering would be needed for real-world use.

## 8. Implementation links

- **Local dashboard (available while the server is running):** http://127.0.0.1:5000
- **GitHub repository:** https://github.com/Poojaiyer-9/Smart-City-Traffic-Camera-Edge-Box
- **Project folder:** `Traffic system edge ai`
- **Main implementation files:** [edge_server.py](./edge_server.py), [crypto_utils.py](./crypto_utils.py), [camera.py](./camera.py), [video_camera.py](./video_camera.py), [templates/index.html](./templates/index.html), [static/js/dashboard.js](./static/js/dashboard.js)
- **Setup instructions:** [README.md](./README.md)
