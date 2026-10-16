"""
Interactive CLI SOC Command Center
A terminal-based interface for security operations, model diagnostics,
live attack simulation, and single-packet inspection.
"""

import sys
import os
import argparse
import json

BANNER = r"""
  ██████╗██╗   ██╗██████╗ ███████╗██████╗      ███████╗ ██████╗  ██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗     ██╔════╝██╔═══██╗██╔════╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝     ███████╗██║   ██║██║     
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗     ╚════██║██║   ██║██║     
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║     ███████║╚██████╔╝╚██████╗
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝
          AI-POWERED THREAT DETECTION & INCIDENT COMMAND CENTER
"""

def print_banner():
    print("\033[96m" + BANNER + "\033[0m")
    print("\033[90m[*] Engine: Hybrid Random Forest + Isolation Forest | SOC Severity: Active\033[0m\n")


def run_interactive_menu():
    print_banner()
    while True:
        print("Select an action:")
        print("  [1] Run End-to-End Pipeline (Data, Train, Evaluate, Simulator)")
        print("  [2] Run Virtual Cyber Attack Simulation")
        print("  [3] Launch Web SOC Dashboard & REST API (port 5050)")
        print("  [4] Inspect a Single Custom Network Packet")
        print("  [5] Run Pytest Automated Test Suite")
        print("  [6] Exit")
        
        choice = input("\nEnter choice (1-6): ").strip()
        
        if choice == "1":
            from main import run_full_pipeline
            run_full_pipeline()
        elif choice == "2":
            from src.simulator import CyberAttackSimulator
            sim = CyberAttackSimulator()
            sim.run_simulation(iterations_per_scenario=3, delay_sec=0.03)
        elif choice == "3":
            from app import app
            port = int(os.environ.get("PORT", 5050))
            print(f"\n[*] Launching SOC Radar at http://127.0.0.1:{port} (Press Ctrl+C to stop)...")
            app.run(host="0.0.0.0", port=port, debug=False)
        elif choice == "4":
            inspect_custom_packet_prompt()
        elif choice == "5":
            import pytest
            pytest.main(["tests/"])
        elif choice == "6":
            print("\n[+] Exiting SOC Command Center. Stay secure!\n")
            sys.exit(0)
        else:
            print("\033[91m[-] Invalid selection. Please enter 1-6.\033[0m\n")


def inspect_custom_packet_prompt():
    from src.threat_engine import ThreatDetectionEngine
    engine = ThreatDetectionEngine()
    print("\n--- Network Packet Inspector ---")
    try:
        proto = input("Protocol (tcp/udp/icmp) [tcp]: ").strip() or "tcp"
        service = input("Service (http/https/ssh/dns/other) [http]: ").strip() or "http"
        duration = float(input("Duration (seconds) [0.0]: ").strip() or "0.0")
        src_bytes = int(input("Source Bytes [40]: ").strip() or "40")
        dst_bytes = int(input("Destination Bytes [0]: ").strip() or "0")
        failed_logins = int(input("Failed Logins [0]: ").strip() or "0")
        count = int(input("Connection Count (past 2s) [400]: ").strip() or "400")
        serror_rate = float(input("SYN Error Rate (0.0 to 1.0) [0.95]: ").strip() or "0.95")
        diff_srv_rate = float(input("Diff Service Rate (0.0 to 1.0) [0.0]: ").strip() or "0.0")

        packet = {
            "protocol_type": proto,
            "service": service,
            "duration": duration,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "failed_logins": failed_logins,
            "count": count,
            "serror_rate": serror_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": 255
        }

        alert = engine.analyze_event(packet)
        print("\n\033[92m=== AI INCIDENT TRIAGE REPORT ===\033[0m")
        print(f"Threat Detected:      {alert['threat_detected']}")
        print(f"Severity Tier:        {alert['severity']}")
        print(f"Composite Risk Score: {alert['risk_score']}/100")
        print(f"Attributed Attack:    {alert['attack_type_attribution']}")
        print(f"Confidence:           {alert['supervised_confidence']}%")
        print(f"Anomaly Outlier:      {alert['anomaly_detected']} (Isolation Score: {alert['isolation_score']})")
        print(f"Recommended Action:   {alert['recommended_action']}\n")
    except Exception as e:
        print(f"\033[91m[-] Error analyzing packet: {e}\033[0m\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Cybersecurity Threat Command Center")
    parser.add_argument("--simulate", action="store_true", help="Run cyber attack simulation")
    parser.add_argument("--dashboard", action="store_true", help="Launch web SOC dashboard")
    parser.add_argument("--pipeline", action="store_true", help="Run full training & evaluation pipeline")
    parser.add_argument("--test", action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.simulate:
        from src.simulator import CyberAttackSimulator
        sim = CyberAttackSimulator()
        sim.run_simulation(iterations_per_scenario=3, delay_sec=0.02)
    elif args.dashboard:
        from app import app
        port = int(os.environ.get("PORT", 5050))
        app.run(host="0.0.0.0", port=port, debug=False)
    elif args.pipeline:
        from main import run_full_pipeline
        run_full_pipeline()
    elif args.test:
        import pytest
        pytest.main(["tests/"])
    else:
        run_interactive_menu()
