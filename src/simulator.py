"""
Virtual Cyber Threat Simulation Module
Simulates live enterprise network traffic including authentic cyber attack vectors:
1. Benign Web Browsing & API Traffic
2. Distributed Denial of Service (DoS SYN Flood)
3. Stealth Port Scanning & Host Reconnaissance
4. SSH Credential Brute Force Attack
5. Covert Data Exfiltration (Zero-day Anomaly)

Feeds synthetic live packets into the ThreatDetectionEngine, logs live telemetry,
and outputs a simulation summary report for SOC analysis.
"""

import time
import json
import random
from datetime import datetime
from src.threat_engine import ThreatDetectionEngine


class CyberAttackSimulator:
    def __init__(self):
        self.engine = ThreatDetectionEngine()

    def generate_packet(self, scenario: str) -> dict:
        """Generates network telemetry matching the requested scenario."""
        if scenario == "Normal_Browsing":
            return {
                "scenario": scenario,
                "duration": round(random.uniform(0.5, 3.2), 2),
                "protocol_type": "tcp",
                "service": random.choice(["http", "https"]),
                "src_bytes": random.randint(300, 800),
                "dst_bytes": random.randint(2000, 8000),
                "failed_logins": 0,
                "logged_in": 1,
                "count": random.randint(1, 8),
                "srv_count": random.randint(1, 8),
                "serror_rate": 0.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": random.randint(10, 80),
                "dst_host_srv_count": random.randint(10, 80)
            }

        elif scenario == "DoS_SYN_Flood":
            return {
                "scenario": scenario,
                "duration": 0.0,
                "protocol_type": "tcp",
                "service": "http",
                "src_bytes": random.randint(20, 60),
                "dst_bytes": 0,
                "failed_logins": 0,
                "logged_in": 0,
                "count": random.randint(300, 500),
                "srv_count": random.randint(300, 500),
                "serror_rate": round(random.uniform(0.92, 1.0), 3),
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 255,
                "dst_host_srv_count": 255
            }

        elif scenario == "Port_Scan_Recon":
            return {
                "scenario": scenario,
                "duration": 0.05,
                "protocol_type": "tcp",
                "service": random.choice(["other", "ftp", "ssh", "smtp", "dns"]),
                "src_bytes": 44,
                "dst_bytes": 0,
                "failed_logins": 0,
                "logged_in": 0,
                "count": random.randint(150, 320),
                "srv_count": 2,
                "serror_rate": 0.5,
                "rerror_rate": 0.5,
                "same_srv_rate": 0.02,
                "diff_srv_rate": 0.98,
                "dst_host_count": 255,
                "dst_host_srv_count": 3
            }

        elif scenario == "SSH_Brute_Force":
            return {
                "scenario": scenario,
                "duration": round(random.uniform(2.0, 5.0), 2),
                "protocol_type": "tcp",
                "service": "ssh",
                "src_bytes": random.randint(250, 400),
                "dst_bytes": random.randint(180, 320),
                "failed_logins": random.randint(4, 9),
                "logged_in": 0,
                "count": random.randint(25, 60),
                "srv_count": random.randint(25, 60),
                "serror_rate": 0.05,
                "rerror_rate": 0.35,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 35,
                "dst_host_srv_count": 35
            }

        elif scenario == "Data_Exfiltration":
            return {
                "scenario": scenario,
                "duration": round(random.uniform(45.0, 120.0), 2),
                "protocol_type": "tcp",
                "service": "https",
                "src_bytes": random.randint(650000, 1800000),  # Massive outbound byte volume
                "dst_bytes": random.randint(300, 900),
                "failed_logins": 0,
                "logged_in": 1,
                "count": 4,
                "srv_count": 4,
                "serror_rate": 0.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 12,
                "dst_host_srv_count": 12
            }
        else:
            raise ValueError(f"Unknown scenario: {scenario}")

    def run_simulation(self, iterations_per_scenario: int = 3, delay_sec: float = 0.05):
        scenarios = [
            ("Normal_Browsing", iterations_per_scenario),
            ("DoS_SYN_Flood", iterations_per_scenario),
            ("Port_Scan_Recon", iterations_per_scenario),
            ("SSH_Brute_Force", iterations_per_scenario),
            ("Data_Exfiltration", iterations_per_scenario)
        ]

        print("\n" + "=" * 70)
        print("   CYBERSECURITY THREAT SIMULATION & LIVE SOC RADAR")
        print("=" * 70)
        print(f"[*] Starting simulation run at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}")
        print(f"[*] Injecting traffic streams across {len(scenarios)} attack categories...\n")

        simulation_log = []
        threat_count = 0
        total_packets = 0

        for scenario_name, count in scenarios:
            print(f">>> Injecting Phase: {scenario_name} ({count} packets)")
            for i in range(count):
                packet = self.generate_packet(scenario_name)
                alert = self.engine.analyze_event(packet)
                total_packets += 1

                if alert["threat_detected"]:
                    threat_count += 1
                    status_symbol = "🚨 [THREAT DETECTED]"
                else:
                    status_symbol = "✅ [BENIGN/SAFE]   "

                print(
                    f"  Packet #{total_packets:02d} | {status_symbol} "
                    f"Severity={alert['severity']:<8} "
                    f"Score={alert['risk_score']:3d}/100 | "
                    f"Type: {alert['attack_type_attribution']}"
                )

                simulation_log.append({
                    "packet_id": total_packets,
                    "injected_scenario": scenario_name,
                    "alert": alert
                })
                time.sleep(delay_sec)
            print("-" * 70)

        # Generate summary report
        report = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
            "total_packets_inspected": total_packets,
            "threats_detected": threat_count,
            "detection_rate_pct": round((threat_count / max(1, total_packets - iterations_per_scenario)) * 100, 2),
            "events": simulation_log
        }

        with open("outputs/simulation_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print("\n" + "=" * 70)
        print("                 SIMULATION SUMMARY")
        print("=" * 70)
        print(f"Total Packets Evaluated:     {total_packets}")
        print(f"Threats Intercepted:         {threat_count}")
        print(f"Benign Traffic Handled:      {total_packets - threat_count}")
        print(f"Simulation Report Saved:     outputs/simulation_report.json")
        print(f"Incident Log Appended:       outputs/threat_alerts.log")
        print("=" * 70 + "\n")
        return report


if __name__ == "__main__":
    sim = CyberAttackSimulator()
    sim.run_simulation(iterations_per_scenario=4, delay_sec=0.02)
