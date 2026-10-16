"""
SOC Web Application & Real-Time REST API
Provides:
1. An interactive SOC Dashboard UI for security analysts
2. A REST API (`/predict`) for real-time packet inspection and SIEM integration
3. Quick-fire simulation presets for live demonstrations
"""

import os
from flask import Flask, request, jsonify, render_template_string
from src.threat_engine import ThreatDetectionEngine

app = Flask(__name__)

# Initialize Threat Detection Engine
engine = None

def get_engine():
    global engine
    if engine is None:
        engine = ThreatDetectionEngine()
    return engine


HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Cybersecurity Threat Radar & SOC Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0e17;
            --card-bg: rgba(18, 26, 43, 0.75);
            --border-glow: rgba(0, 240, 255, 0.25);
            --cyan-glow: #00f0ff;
            --red-alert: #ff0055;
            --amber-warn: #ffb800;
            --green-safe: #00ff88;
            --text-main: #e2e8f0;
            --text-muted: #8b9bb4;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, rgba(0, 240, 255, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(255, 0, 85, 0.08) 0px, transparent 50%);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            padding: 24px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 18px;
            margin-bottom: 24px;
        }

        .title-block h1 {
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .pulse-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--green-safe);
            box-shadow: 0 0 12px var(--green-safe);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(0, 255, 136, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 136, 0); }
        }

        .status-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            background: rgba(0, 240, 255, 0.1);
            border: 1px solid var(--border-glow);
            padding: 6px 14px;
            border-radius: 20px;
            color: var(--cyan-glow);
        }

        .grid-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        @media (max-width: 900px) {
            .grid-container { grid-template-columns: 1fr; }
        }

        .card {
            background: var(--card-bg);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 24px;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        .card h2 {
            font-size: 18px;
            margin-bottom: 16px;
            color: var(--text-main);
            border-left: 3px solid var(--cyan-glow);
            padding-left: 10px;
        }

        .quick-presets {
            display: flex;
            gap: 8px;
            margin-bottom: 18px;
            flex-wrap: wrap;
        }

        .btn-preset {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: var(--text-main);
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-preset:hover {
            background: rgba(0, 240, 255, 0.15);
            border-color: var(--cyan-glow);
            color: var(--cyan-glow);
        }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        label {
            font-size: 12px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }

        input, select {
            background: rgba(10, 14, 23, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: #fff;
            padding: 8px 12px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }

        input:focus, select:focus {
            outline: none;
            border-color: var(--cyan-glow);
            box-shadow: 0 0 8px rgba(0, 240, 255, 0.3);
        }

        .btn-analyze {
            grid-column: span 2;
            background: linear-gradient(135deg, #00f0ff, #0077fe);
            color: #050a14;
            font-weight: 700;
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            cursor: pointer;
            margin-top: 10px;
            transition: opacity 0.2s;
        }

        .btn-analyze:hover {
            opacity: 0.9;
        }

        .result-panel {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .score-gauge-box {
            display: flex;
            align-items: center;
            justify-content: space-around;
            background: rgba(0, 0, 0, 0.3);
            padding: 18px;
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .score-circle {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 4px solid var(--green-safe);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 800;
            font-size: 26px;
            color: var(--green-safe);
            transition: all 0.3s;
        }

        .score-circle span {
            font-size: 10px;
            font-weight: 400;
            color: var(--text-muted);
        }

        .severity-banner {
            padding: 12px 18px;
            border-radius: 8px;
            font-weight: 700;
            letter-spacing: 0.5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(0, 255, 136, 0.1);
            color: var(--green-safe);
            border: 1px solid rgba(0, 255, 136, 0.3);
        }

        .stats-table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }

        .stats-table td {
            padding: 8px 6px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .stats-table td:first-child {
            color: var(--text-muted);
        }

        .action-box {
            background: rgba(255, 0, 85, 0.08);
            border-left: 3px solid var(--red-alert);
            padding: 12px 16px;
            border-radius: 4px;
            font-size: 13px;
        }
    </style>
</head>
<body>

    <header>
        <div class="title-block">
            <div class="pulse-indicator"></div>
            <h1>AI CYBER THREAT RADAR</h1>
        </div>
        <div class="status-badge">HYBRID AI ENGINE: ONLINE</div>
    </header>

    <div class="grid-container">
        <!-- Live Packet Inspector -->
        <div class="card">
            <h2>NETWORK PACKET INSPECTOR</h2>
            <div class="quick-presets">
                <button class="btn-preset" onclick="loadPreset('normal')">Preset: Normal Web</button>
                <button class="btn-preset" onclick="loadPreset('synflood')">Preset: SYN Flood DoS</button>
                <button class="btn-preset" onclick="loadPreset('portscan')">Preset: Port Scan</button>
                <button class="btn-preset" onclick="loadPreset('brute')">Preset: SSH Brute Force</button>
                <button class="btn-preset" onclick="loadPreset('exfil')">Preset: Data Exfiltration</button>
            </div>

            <form id="packetForm" class="form-grid" onsubmit="event.preventDefault(); analyzePacket();">
                <div class="form-group">
                    <label>Protocol Type</label>
                    <select id="protocol_type">
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                        <option value="icmp">ICMP</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Target Service</label>
                    <select id="service">
                        <option value="http">HTTP</option>
                        <option value="https">HTTPS</option>
                        <option value="ssh">SSH</option>
                        <option value="ftp">FTP</option>
                        <option value="dns">DNS</option>
                        <option value="other">OTHER</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Duration (sec)</label>
                    <input type="number" step="0.1" id="duration" value="1.5">
                </div>
                <div class="form-group">
                    <label>Failed Logins</label>
                    <input type="number" id="failed_logins" value="0">
                </div>
                <div class="form-group">
                    <label>Source Bytes (Payload)</label>
                    <input type="number" id="src_bytes" value="450">
                </div>
                <div class="form-group">
                    <label>Destination Bytes</label>
                    <input type="number" id="dst_bytes" value="3500">
                </div>
                <div class="form-group">
                    <label>Count (2s Connections)</label>
                    <input type="number" id="count" value="4">
                </div>
                <div class="form-group">
                    <label>SYN Error Rate (0.0 - 1.0)</label>
                    <input type="number" step="0.01" id="serror_rate" value="0.0">
                </div>
                <div class="form-group">
                    <label>Diff Service Rate (0.0 - 1.0)</label>
                    <input type="number" step="0.01" id="diff_srv_rate" value="0.0">
                </div>
                <div class="form-group">
                    <label>Dest Host Count (0 - 255)</label>
                    <input type="number" id="dst_host_count" value="45">
                </div>
                <button type="submit" class="btn-analyze">⚡ INSPECT PACKET WITH AI</button>
            </form>
        </div>

        <!-- SOC Decision & Analysis Feed -->
        <div class="card result-panel">
            <h2>SECURITY INCIDENT TELEMETRY</h2>

            <div id="severityBanner" class="severity-banner">
                <span id="threatStatus">STATUS: ALL CLEAR</span>
                <span id="severityLevel">BENIGN</span>
            </div>

            <div class="score-gauge-box">
                <div id="scoreCircle" class="score-circle">
                    <div id="riskScoreVal">08</div>
                    <span>RISK SCORE</span>
                </div>
                <div>
                    <h3 id="attackAttribution" style="font-size: 16px; margin-bottom: 6px;">Normal Traffic</h3>
                    <p style="font-size: 12px; color: var(--text-muted);">Attribution by Random Forest + Isolation Forest</p>
                </div>
            </div>

            <table class="stats-table">
                <tr>
                    <td>Supervised Threat Confidence</td>
                    <td id="supConf">2.4%</td>
                </tr>
                <tr>
                    <td>Unsupervised Anomaly Flag</td>
                    <td id="anoFlag">Normal (Inlier)</td>
                </tr>
                <tr>
                    <td>Isolation Anomaly Score</td>
                    <td id="isoVal">+0.142</td>
                </tr>
                <tr>
                    <td>Detection Timestamp</td>
                    <td id="timestamp">Just now</td>
                </tr>
            </table>

            <div class="action-box">
                <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">Recommended SOC Mitigation</div>
                <div id="recAction" style="font-weight: 600;">Allow Traffic (No Anomalies Detected)</div>
            </div>
        </div>
    </div>

    <script>
        const presets = {
            normal: {
                protocol_type: "tcp", service: "http", duration: 1.2,
                failed_logins: 0, src_bytes: 420, dst_bytes: 3800,
                count: 5, serror_rate: 0.0, diff_srv_rate: 0.0, dst_host_count: 30
            },
            synflood: {
                protocol_type: "tcp", service: "http", duration: 0.0,
                failed_logins: 0, src_bytes: 40, dst_bytes: 0,
                count: 450, serror_rate: 0.98, diff_srv_rate: 0.0, dst_host_count: 255
            },
            portscan: {
                protocol_type: "tcp", service: "other", duration: 0.05,
                failed_logins: 0, src_bytes: 44, dst_bytes: 0,
                count: 220, serror_rate: 0.5, diff_srv_rate: 0.95, dst_host_count: 255
            },
            brute: {
                protocol_type: "tcp", service: "ssh", duration: 3.5,
                failed_logins: 6, src_bytes: 320, dst_bytes: 240,
                count: 40, serror_rate: 0.0, diff_srv_rate: 0.0, dst_host_count: 25
            },
            exfil: {
                protocol_type: "tcp", service: "https", duration: 90.0,
                failed_logins: 0, src_bytes: 850000, dst_bytes: 450,
                count: 3, serror_rate: 0.0, diff_srv_rate: 0.0, dst_host_count: 10
            }
        };

        function loadPreset(name) {
            const p = presets[name];
            for (let k in p) {
                const el = document.getElementById(k);
                if (el) el.value = p[k];
            }
            analyzePacket();
        }

        async function analyzePacket() {
            const payload = {
                protocol_type: document.getElementById('protocol_type').value,
                service: document.getElementById('service').value,
                duration: parseFloat(document.getElementById('duration').value) || 0,
                failed_logins: parseInt(document.getElementById('failed_logins').value) || 0,
                src_bytes: parseInt(document.getElementById('src_bytes').value) || 0,
                dst_bytes: parseInt(document.getElementById('dst_bytes').value) || 0,
                count: parseInt(document.getElementById('count').value) || 0,
                serror_rate: parseFloat(document.getElementById('serror_rate').value) || 0,
                diff_srv_rate: parseFloat(document.getElementById('diff_srv_rate').value) || 0,
                dst_host_count: parseInt(document.getElementById('dst_host_count').value) || 0,
                logged_in: 0,
                srv_count: 1,
                rerror_rate: 0.0,
                same_srv_rate: 1.0,
                dst_host_srv_count: 10
            };

            try {
                const res = await fetch('/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                renderResults(data);
            } catch (err) {
                console.error("Analysis error:", err);
            }
        }

        function renderResults(data) {
            document.getElementById('riskScoreVal').innerText = data.risk_score;
            document.getElementById('attackAttribution').innerText = data.attack_type_attribution;
            document.getElementById('supConf').innerText = data.supervised_confidence + '%';
            document.getElementById('anoFlag').innerText = data.anomaly_detected ? 'ANOMALY (Outlier)' : 'Normal (Inlier)';
            document.getElementById('isoVal').innerText = data.isolation_score;
            document.getElementById('timestamp').innerText = data.timestamp;
            document.getElementById('recAction').innerText = data.recommended_action;
            document.getElementById('severityLevel').innerText = data.severity;

            const banner = document.getElementById('severityBanner');
            const circle = document.getElementById('scoreCircle');
            const status = document.getElementById('threatStatus');

            if (data.severity === 'CRITICAL' || data.severity === 'HIGH') {
                banner.style.background = 'rgba(255, 0, 85, 0.15)';
                banner.style.color = '#ff0055';
                banner.style.borderColor = 'rgba(255, 0, 85, 0.5)';
                circle.style.borderColor = '#ff0055';
                circle.style.color = '#ff0055';
                status.innerText = '🚨 THREAT INTERCEPTED';
            } else if (data.severity === 'MEDIUM') {
                banner.style.background = 'rgba(255, 184, 0, 0.15)';
                banner.style.color = '#ffb800';
                banner.style.borderColor = 'rgba(255, 184, 0, 0.5)';
                circle.style.borderColor = '#ffb800';
                circle.style.color = '#ffb800';
                status.innerText = '⚠️ SUSPICIOUS ANOMALY';
            } else {
                banner.style.background = 'rgba(0, 255, 136, 0.15)';
                banner.style.color = '#00ff88';
                banner.style.borderColor = 'rgba(0, 255, 136, 0.5)';
                circle.style.borderColor = '#00ff88';
                circle.style.color = '#00ff88';
                status.innerText = '✅ BENIGN TRAFFIC';
            }
        }
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_DASHBOARD)


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        eng = get_engine()
        result = eng.analyze_event(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "AI-Cybersecurity-Threat-Detection-API",
        "models_loaded": True
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"[*] Starting AI Cybersecurity SOC Radar at http://127.0.0.1:{port} ...")
    app.run(host="0.0.0.0", port=port, debug=False)
