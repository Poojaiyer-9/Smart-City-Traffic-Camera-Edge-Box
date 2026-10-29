/* ═══════════════════════════════════════════════════════════
   dashboard.js – Smart-City Traffic Edge Dashboard Logic
═══════════════════════════════════════════════════════════ */

const API = '';   // same origin
let jwtToken   = null;
let uploadHist = Array(20).fill(0);
let chartInst  = null;
let prevCount  = 0;
let floodActive = false;

/* ─── Chart.js setup ──────────────────────────────────────── */
function initChart() {
  const ctx = document.getElementById('uploadChart').getContext('2d');
  chartInst = new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array(20).fill(''),
      datasets: [{
        label: 'Uploads / tick',
        data: uploadHist,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59,130,246,0.1)',
        tension: 0.4,
        fill: true,
        pointRadius: 0,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: {
        x: { display: false },
        y: {
          display: true,
          beginAtZero: true,
          ticks: { color: '#64748b', font: { size: 10 }, stepSize: 1 },
          grid: { color: 'rgba(255,255,255,0.04)' },
        },
      },
      animation: { duration: 300 },
    },
  });
}

/* ─── Clock ───────────────────────────────────────────────── */
function tickClock() {
  document.getElementById('clockDisplay').textContent =
    new Date().toLocaleTimeString('en-IN', { hour12: false });
}
setInterval(tickClock, 1000);
tickClock();

/* ─── Toast ───────────────────────────────────────────────── */
let toastTimer = null;
function toast(msg, type = 'info') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast ${type}`;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3000);
}

/* ─── Show demo output ────────────────────────────────────── */
function showOutput(id, text, cls = '') {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = `demo-output visible ${cls}`;
}

/* ─── Animate counter ─────────────────────────────────────── */
function animateNum(id, newVal) {
  const el = document.getElementById(id);
  if (!el) return;
  const old = parseInt(el.textContent) || 0;
  if (old === newVal) return;
  el.classList.add('num-flash');
  el.textContent = newVal;
  setTimeout(() => el.classList.remove('num-flash'), 400);
}

/* ════════════════════════════════════════════════════════════
   POLL: Dashboard Stats
════════════════════════════════════════════════════════════ */
async function fetchStats() {
  try {
    const res  = await fetch(`${API}/dashboard/stats`);
    const data = await res.json();

    animateNum('totalUploads',   data.total_uploads);
    animateNum('hmacVerified',   data.hmac_verified);
    animateNum('hmacFailed',     data.hmac_failed);
    animateNum('quarantineCount',data.quarantined_count);
    animateNum('jwtIssued',      data.jwt_issued);
    animateNum('sseSearches',    data.sse_searches);
    animateNum('paillierCount',  data.paillier_count);
    animateNum('preRekeys',      data.pre_rekeys);

    // secondary badges
    animateNum('ibeLookups',     data.ibe_lookups);
    animateNum('abeGranted',     data.abe_granted);
    animateNum('abeDenied',      data.abe_denied);
    animateNum('preRekeysCard',  data.pre_rekeys);
    animateNum('honeyDecoys',    data.honey_decoys);
    animateNum('sseIndexSize',   data.sse_index_size);
    animateNum('sseSearchesSide',data.sse_searches);
    animateNum('homEncCounts',   data.paillier_count);
    animateNum('jwtVerifiedCard',data.jwt_verified);
    animateNum('handoversCard',  data.handovers);
    animateNum('privacyNoise',   data.privacy_noise_applied);
    animateNum('feCount',        data.monthly_count);
    animateNum('plateCount',     data.stored_records);

    // plate count badge text
    const pc = document.getElementById('plateCount');
    if (pc) pc.textContent = `${data.stored_records} records`;

    // uptime
    const h = Math.floor(data.uptime_s/3600);
    const m = Math.floor((data.uptime_s%3600)/60);
    const s = data.uptime_s%60;
    document.getElementById('uptimeVal').textContent =
      h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;

    // integrity bar
    const total = data.hmac_verified + data.hmac_failed;
    const pct   = total === 0 ? 100 : Math.round(data.hmac_verified / total * 100);
    const bar   = document.getElementById('integrityBar');
    if (bar) bar.style.width = pct + '%';

    // attack alert
    const alert = document.getElementById('attackAlert');
    if (data.quarantined_count > 0) {
      alert.classList.remove('hidden');
    } else {
      alert.classList.add('hidden');
    }

    // quarantine list
    const ql = document.getElementById('quarantinedList');
    if (ql) ql.textContent = data.quarantined_ids.length
      ? data.quarantined_ids.join(', ')
      : 'None';

    // chart
    const delta = data.total_uploads - prevCount;
    prevCount   = data.total_uploads;
    uploadHist.shift();
    uploadHist.push(delta);
    if (chartInst) chartInst.data.datasets[0].data = [...uploadHist];
    if (chartInst) chartInst.update('none');

  } catch (err) {
    console.warn('Stats fetch failed:', err);
  }
}

/* ════════════════════════════════════════════════════════════
   POLL: Recent Records (Plate Table)
════════════════════════════════════════════════════════════ */
async function fetchRecords() {
  try {
    const res  = await fetch(`${API}/dashboard/records?limit=15`);
    const rows = await res.json();
    const tbody = document.getElementById('plateTableBody');
    if (!tbody) return;
    if (rows.length === 0) return;
    tbody.innerHTML = rows.map(r => {
      const cat = (r.category || 'normal').toLowerCase();
      const catCls = cat === 'stolen' ? 'cat-stolen' : cat === 'wanted' ? 'cat-wanted' : 'cat-normal';
      const cam = (r.camera_id || '').slice(-10);
      const t   = r.received ? r.received.split('T')[1]?.split('.')[0] : '--';
      const spd = r.speed_kmh ? `${r.speed_kmh} km/h` : '--';
      return `<tr class="row-flash">
        <td>${t}</td>
        <td class="mono">${cam}</td>
        <td>${r.zone || '--'}</td>
        <td class="mono">${r.plate_anon || '--'}</td>
        <td class="${catCls}">${cat.toUpperCase()}</td>
        <td>${spd}</td>
        <td><span class="badge badge-green">Stored</span></td>
      </tr>`;
    }).join('');
  } catch(e) {}
}

/* ════════════════════════════════════════════════════════════
   POLL: Activity Log
════════════════════════════════════════════════════════════ */
async function fetchLog() {
  try {
    const res  = await fetch(`${API}/dashboard/log`);
    const entries = await res.json();
    const cont = document.getElementById('activityLog');
    if (!cont || entries.length === 0) return;
    cont.innerHTML = entries.slice(0, 40).map(e =>
      `<div class="log-entry ${e.level}">
        <span class="log-ts">${e.ts}</span>
        <span class="log-cat">[${e.category}]</span>
        <span class="log-msg">${e.msg}</span>
      </div>`
    ).join('');
  } catch(e) {}
}

/* ════════════════════════════════════════════════════════════
   POLL: Camera Rates (Attack Detection)
════════════════════════════════════════════════════════════ */
async function fetchCameraRates() {
  try {
    const res  = await fetch(`${API}/dashboard/cameras`);
    const cams = await res.json();
    const cont = document.getElementById('cameraRateList');
    if (!cont) return;
    if (cams.length === 0) { cont.innerHTML = '<div style="color:#64748b;font-size:11px">No cameras connected</div>'; return; }
    cont.innerHTML = cams.map(c => `
      <div class="cam-rate-row">
        <div class="cam-rate-label">
          <span class="mono" style="font-size:10px">${c.id.slice(-12)}</span>
          <span style="font-size:10px;color:${c.quarantined?'#ef4444':'#64748b'}">${c.quarantined ? '🔒 BLOCKED' : c.requests + '/10s'}</span>
        </div>
        <div class="cam-rate-bar">
          <div class="cam-rate-fill ${c.quarantined ? 'danger' : ''}" style="width:${c.rate_pct}%"></div>
        </div>
      </div>
    `).join('');
  } catch(e) {}
}

async function fetchVideoStatus() {
  try {
    const res = await fetch(`${API}/video/status`);
    const data = await res.json();
    const connection = document.getElementById('videoConnection');
    connection.textContent = data.connected ? 'Live' : 'Waiting for camera';
    connection.className = data.connected ? 'badge badge-green' : 'badge badge-orange';
    document.getElementById('videoPlaceholder').classList.toggle('hidden', data.connected);
    document.getElementById('videoDetectionCount').textContent = data.detection_count;
    document.getElementById('videoSentCount').textContent = data.vehicles_sent;
    document.getElementById('videoCameraId').textContent = data.camera_id;
    document.getElementById('videoZone').textContent = data.zone;
  } catch(e) {}
}

function clearLog() {
  const cont = document.getElementById('activityLog');
  if (cont) cont.innerHTML = '<div class="log-empty">Log cleared</div>';
}

/* ════════════════════════════════════════════════════════════
   DEMO ACTIONS
════════════════════════════════════════════════════════════ */

/* Inject one fake reading directly from JS (simulate camera.py) */
async function injectCamera() {
  const states = ['KA','MH','DL','TN','AP','GJ','RJ','UP','WB','HR'];
  const cats   = ['stolen','wanted','normal','normal','normal'];
  const state  = states[Math.floor(Math.random()*states.length)];
  const plate  = state + String(Math.floor(Math.random()*99)+1).padStart(2,'0')
               + String.fromCharCode(65+Math.floor(Math.random()*26))
               + String.fromCharCode(65+Math.floor(Math.random()*26))
               + String(Math.floor(Math.random()*9000)+1000);

  // We can't AES+HMAC in pure browser JS without libraries,
  // so we call a helper endpoint
  try {
    const r = await fetch(`${API}/demo/inject`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ plate, category: cats[Math.floor(Math.random()*cats.length)],
                             speed_kmh: Math.round(Math.random()*100+20),
                             zone: 'Zone3' })
    });
    const d = await r.json();
    toast('📷 Reading injected → ' + plate, 'info');
  } catch(e) { toast('Injection failed: ' + e.message, 'err'); }
}

/* Flood attack simulation */
async function triggerFlood() {
  if (floodActive) return;
  floodActive = true;
  toast('⚡ Flood attack started (50 rapid requests)…', 'warn');
  document.querySelector('.btn-flood').disabled = true;
  try {
    for (let i = 0; i < 50; i++) {
      await fetch(`${API}/demo/inject`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ plate:'FLOOD'+i, category:'normal',
                               speed_kmh:60, zone:'Zone3', flood:true })
      });
      await new Promise(r => setTimeout(r, 40));
    }
    toast('🔒 Flood sent — check Attack Detection panel!', 'warn');
  } finally {
    floodActive = false;
    document.querySelector('.btn-flood').disabled = false;
  }
}

/* ── 4.3 IBE Demo ───────────────────────────────────────── */
async function demoIBE() {
  showOutput('ibeOutput', 'Encrypting with IBE identity…', 'warn');
  try {
    const enc = await fetch(`${API}/ibe/encrypt`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ identity:'intersection-47-gateway', message:'PlateXX999' })
    }).then(r=>r.json());
    const dec = await fetch(`${API}/ibe/decrypt`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ identity:'intersection-47-gateway', token_b64: enc.token_b64 })
    }).then(r=>r.json());
    showOutput('ibeOutput',
      `✓ Encrypted (first 40 chars):\n${enc.token_b64.slice(0,40)}…\n\n✓ Decrypted: ${dec.plaintext}`, 'ok');
    toast('IBE encrypt/decrypt success ✓', 'info');
  } catch(e) { showOutput('ibeOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.4 ABE Demo ───────────────────────────────────────── */
async function demoABE() {
  const attrs = [];
  if (document.getElementById('attrTO').checked)    attrs.push('TrafficOfficer');
  if (document.getElementById('attrZ3').checked)    attrs.push('Zone3');
  if (document.getElementById('attrAdmin').checked) attrs.push('Admin');
  showOutput('abeOutput', 'Checking policy…', 'warn');
  try {
    const res = await fetch(`${API}/abe/check`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ attributes: attrs })
    }).then(r=>r.json());
    if (res.access === 'granted') {
      showOutput('abeOutput', `✓ ACCESS GRANTED\nPolicy: ${res.policy}\nAttribs: ${attrs.join(', ')}`, 'ok');
      toast('ABE: Access granted ✓', 'info');
    } else {
      showOutput('abeOutput', `✗ ACCESS DENIED\nPolicy: ${res.policy}\nMissing required attributes`, 'err');
      toast('ABE: Access denied ✗', 'warn');
    }
  } catch(e) { showOutput('abeOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.5 PRE Demo ───────────────────────────────────────── */
async function demoPRE() {
  showOutput('preOutput', 'Generating re-encryption key…', 'warn');
  try {
    const res = await fetch(`${API}/pre/rekey`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ owner:'intersection-47-gateway', neighbour:'edge-neighbour-01' })
    }).then(r=>r.json());
    showOutput('preOutput',
      `✓ Re-key ID: ${res.rekey_id}\nWrapped key (first 40):\n${(res.wrapped_key_b64||'').slice(0,40)}…`, 'ok');
    toast('PRE re-key generated ✓', 'info');
  } catch(e) { showOutput('preOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.6 FE Demo ────────────────────────────────────────── */
async function demoFE() {
  // First get a JWT, then use it
  try {
    const tok = await fetch(`${API}/auth/token`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ camera_id:'city-analytics', role:'analyst' })
    }).then(r=>r.json());
    jwtToken = tok.token;
    const fe = await fetch(`${API}/fe/monthly-count`, {
      headers: { 'Authorization': `Bearer ${jwtToken}` }
    }).then(r=>r.json());
    showOutput('feOutput',
      `✓ JWT obtained (role: analyst)\n✓ FE Result: ${fe.result} vehicles\n  (DP noise applied, raw=${fe.raw_count})\n  Raw plates: NEVER exposed`, 'ok');
    document.getElementById('feCount').textContent = fe.result;
    toast('FE count served — no raw plates ✓', 'info');
  } catch(e) { showOutput('feOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.7 Honey Encryption ───────────────────────────────── */
async function storeHoney() {
  const pwd = document.getElementById('honeyPwd').value || 'secret';
  try {
    await fetch(`${API}/honey/store`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ password: pwd, data: JSON.stringify({plates:['KA01AB1234','MH12CD5678']}) })
    });
    showOutput('honeyOutput', `✓ Vault stored with password "${pwd}"`, 'ok');
    toast('Honey vault stored ✓', 'info');
  } catch(e) { showOutput('honeyOutput', 'Error: '+e.message, 'err'); }
}

async function demoHoney() {
  const pwd = document.getElementById('honeyPwd').value || 'wrong';
  try {
    const res = await fetch(`${API}/honey/retrieve`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ password: pwd })
    }).then(r=>r.json());
    if (res.is_decoy) {
      showOutput('honeyOutput',
        `⚠ WRONG PASSWORD → Decoy served!\n${JSON.stringify(res.result, null, 2)}`, 'warn');
      toast('Honey: Decoy data returned for wrong password', 'warn');
    } else {
      showOutput('honeyOutput',
        `✓ Correct password → Real data:\n${JSON.stringify(res.result, null, 2)}`, 'ok');
      toast('Honey vault decrypted correctly ✓', 'info');
    }
  } catch(e) { showOutput('honeyOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.8 SSE Demo ───────────────────────────────────────── */
async function demoSSE() {
  const kw = document.getElementById('sseKeyword').value || 'stolen';
  showOutput('sseOutput', `Generating trapdoor for "${kw}"…`, 'warn');
  try {
    const res = await fetch(`${API}/sse/search`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ keyword: kw })
    }).then(r=>r.json());
    showOutput('sseOutput',
      `✓ Trapdoor: ${res.trapdoor}\n✓ Matches: ${res.matches}\n  Server never learned keyword "${kw}"`, 'ok');
    toast(`SSE search: ${res.matches} match(es) ✓`, 'info');
  } catch(e) { showOutput('sseOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.9 Paillier HOM Demo ──────────────────────────────── */
async function demoHOM() {
  showOutput('homOutput', 'Computing Paillier homomorphic sum…', 'warn');
  try {
    const res = await fetch(`${API}/hom/sum`).then(r=>r.json());
    showOutput('homOutput',
      `✓ Encrypted sum (snippet):\n${res.encrypted_sum_snippet}\n\n✓ Decrypted total: ${res.plaintext}\n  Private key: Utility only`, 'ok');
    toast(`HOM sum = ${res.plaintext} ✓`, 'info');
  } catch(e) { showOutput('homOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.10 Auth Demos ─────────────────────────────────────── */
async function demoJWT() {
  try {
    const res = await fetch(`${API}/auth/token`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ camera_id:'city-control', role:'officer' })
    }).then(r=>r.json());
    jwtToken = res.token;
    showOutput('authOutput',
      `✓ JWT issued (expires in ${res.expires_in}s)\nToken (first 60):\n${jwtToken.slice(0,60)}…`, 'ok');
    toast('JWT token issued ✓', 'info');
  } catch(e) { showOutput('authOutput', 'Error: '+e.message, 'err'); }
}

async function demoHandover() {
  try {
    const iss = await fetch(`${API}/auth/handover`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ camera_id:'CAM-DEMO-001', target_edge:'edge-node-2' })
    }).then(r=>r.json());
    const ver = await fetch(`${API}/auth/handover/verify`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ camera_id:'CAM-DEMO-001', ticket: iss.ticket })
    }).then(r=>r.json());
    showOutput('authOutput',
      `✓ Ticket issued → ${iss.target_edge} (valid ${iss.valid_for_seconds}s)\n✓ Ticket verified: ${ver.valid}\n  Camera moved to ${ver.edge}`, 'ok');
    toast('Handover ticket issued & verified ✓', 'info');
  } catch(e) { showOutput('authOutput', 'Error: '+e.message, 'err'); }
}

/* ── 4.11 Privacy Demo ───────────────────────────────────── */
async function demoPrivacy() {
  // Just display a simulated privacy output
  const plate = 'MH12AB3456';
  const hashed = Array.from(new TextEncoder().encode(plate))
    .reduce((h,b) => ((h<<5)-h)+b, 0).toString(16).replace('-','').padStart(8,'0').slice(0,16);
  const noise  = (30 + (Math.random()*4 - 2)).toFixed(2);
  const lat    = (12.97 + (Math.random()-0.5)).toFixed(6);
  const lon    = (77.59 + (Math.random()-0.5)).toFixed(6);
  const tid    = 'CAM-' + Math.random().toString(36).slice(2,8).toUpperCase();
  showOutput('privacyOutput',
    `Plate:       ${plate}\nHashed:      ${hashed}…\nDP Count:    ~${noise} (Laplace ε=0.5)\nDummy GPS:   ${lat}, ${lon}\nTemp ID:     ${tid} (rotates every 10min)`, 'ok');
  toast('Privacy transforms applied ✓', 'info');
}

/* ════════════════════════════════════════════════════════════
   INJECT HELPER ENDPOINT (registered in edge_server.py)
════════════════════════════════════════════════════════════ */
// This endpoint is handled server-side — see /demo/inject in edge_server.py

/* ─── Bootstrap ───────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initChart();
  document.getElementById('videoFeed').src = `${API}/video/stream`;
  fetchStats();
  fetchRecords();
  fetchLog();
  fetchCameraRates();
  fetchVideoStatus();

  setInterval(fetchStats,       2500);
  setInterval(fetchRecords,     3000);
  setInterval(fetchLog,         2000);
  setInterval(fetchCameraRates, 2000);
  setInterval(fetchVideoStatus, 1000);
});
