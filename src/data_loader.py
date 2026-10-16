"""
Data Loader & Dataset Generator Module
Provides utilities to load existing datasets (NSL-KDD, CICIDS, or custom CSVs)
and generates realistic simulated network connection logs with labeled attacks.
"""

import os
import numpy as np
import pandas as pd


def generate_synthetic_cyber_dataset(n_samples: int = 12000, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a realistic multi-class network traffic dataset mimicking
    features from NSL-KDD / CICIDS2017 for enterprise threat detection.
    
    Attack classes included:
    - Normal (70%)
    - DoS_SYN_Flood (12%)
    - Port_Scan (8%)
    - Brute_Force_SSH (6%)
    - Data_Exfiltration (4%)
    """
    np.random.seed(random_state)
    
    classes = ["Normal", "DoS_SYN_Flood", "Port_Scan", "Brute_Force_SSH", "Data_Exfiltration"]
    probs = [0.70, 0.12, 0.08, 0.06, 0.04]
    
    attack_types = np.random.choice(classes, size=n_samples, p=probs)
    
    records = []
    for attack in attack_types:
        if attack == "Normal":
            proto = np.random.choice(["tcp", "udp"], p=[0.75, 0.25])
            service = np.random.choice(["http", "https", "dns", "smtp"], p=[0.45, 0.35, 0.15, 0.05])
            duration = np.random.exponential(scale=2.0)
            src_bytes = int(np.random.normal(loc=450, scale=150))
            src_bytes = max(40, src_bytes)
            dst_bytes = int(np.random.normal(loc=3500, scale=1200))
            dst_bytes = max(100, dst_bytes)
            failed_logins = 0 if np.random.rand() > 0.02 else 1
            logged_in = 1 if service in ["http", "https", "smtp"] else 0
            count = int(np.random.poisson(lam=5))
            srv_count = max(1, int(count * np.random.uniform(0.6, 1.0)))
            serror_rate = np.random.uniform(0.0, 0.05)
            rerror_rate = np.random.uniform(0.0, 0.05)
            same_srv_rate = np.random.uniform(0.85, 1.0)
            diff_srv_rate = np.random.uniform(0.0, 0.15)
            dst_host_count = int(np.random.uniform(20, 150))
            dst_host_srv_count = int(np.random.uniform(20, 150))
            is_threat = 0

        elif attack == "DoS_SYN_Flood":
            proto = "tcp"
            service = "http"
            duration = 0.0
            src_bytes = int(np.random.uniform(0, 60))
            dst_bytes = 0
            failed_logins = 0
            logged_in = 0
            count = int(np.random.uniform(200, 511))
            srv_count = count
            serror_rate = np.random.uniform(0.90, 1.0)
            rerror_rate = np.random.uniform(0.0, 0.1)
            same_srv_rate = 1.0
            diff_srv_rate = 0.0
            dst_host_count = 255
            dst_host_srv_count = 255
            is_threat = 1

        elif attack == "Port_Scan":
            proto = np.random.choice(["tcp", "icmp"], p=[0.8, 0.2])
            service = np.random.choice(["other", "http", "ftp", "ssh", "dns"])
            duration = np.random.uniform(0.0, 0.2)
            src_bytes = int(np.random.uniform(0, 80))
            dst_bytes = 0
            failed_logins = 0
            logged_in = 0
            count = int(np.random.uniform(80, 350))
            srv_count = int(np.random.uniform(1, 5))
            serror_rate = np.random.uniform(0.3, 0.8)
            rerror_rate = np.random.uniform(0.4, 0.9)
            same_srv_rate = np.random.uniform(0.0, 0.1)
            diff_srv_rate = np.random.uniform(0.8, 1.0)
            dst_host_count = int(np.random.uniform(100, 255))
            dst_host_srv_count = int(np.random.uniform(1, 10))
            is_threat = 1

        elif attack == "Brute_Force_SSH":
            proto = "tcp"
            service = "ssh"
            duration = np.random.uniform(1.0, 6.0)
            src_bytes = int(np.random.uniform(200, 450))
            dst_bytes = int(np.random.uniform(150, 300))
            failed_logins = int(np.random.choice([3, 4, 5, 6, 8, 12]))
            logged_in = 0 if np.random.rand() > 0.05 else 1
            count = int(np.random.uniform(15, 60))
            srv_count = count
            serror_rate = np.random.uniform(0.0, 0.1)
            rerror_rate = np.random.uniform(0.1, 0.5)
            same_srv_rate = 1.0
            diff_srv_rate = 0.0
            dst_host_count = int(np.random.uniform(10, 50))
            dst_host_srv_count = int(np.random.uniform(10, 50))
            is_threat = 1

        else: # Data_Exfiltration
            proto = "tcp"
            service = np.random.choice(["https", "ftp", "dns"], p=[0.6, 0.3, 0.1])
            duration = np.random.uniform(25.0, 180.0)
            src_bytes = int(np.random.uniform(250000, 1500000))  # Huge outbound byte surge
            dst_bytes = int(np.random.uniform(120, 800))
            failed_logins = 0
            logged_in = 1
            count = int(np.random.uniform(1, 10))
            srv_count = int(np.random.uniform(1, 10))
            serror_rate = 0.0
            rerror_rate = 0.0
            same_srv_rate = 1.0
            diff_srv_rate = 0.0
            dst_host_count = int(np.random.uniform(1, 30))
            dst_host_srv_count = int(np.random.uniform(1, 30))
            is_threat = 1

        records.append({
            "duration": round(float(duration), 3),
            "protocol_type": proto,
            "service": service,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "failed_logins": failed_logins,
            "logged_in": logged_in,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": round(float(serror_rate), 4),
            "rerror_rate": round(float(rerror_rate), 4),
            "same_srv_rate": round(float(same_srv_rate), 4),
            "diff_srv_rate": round(float(diff_srv_rate), 4),
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "attack_type": attack,
            "is_threat": is_threat
        })

    df = pd.DataFrame(records)
    return df


def load_or_create_dataset(csv_path: str = "data/raw/sample_network_traffic.csv") -> pd.DataFrame:
    """Loads dataset from disk if present; otherwise creates and saves benchmark dataset."""
    if os.path.exists(csv_path):
        print(f"[+] Loading existing dataset from {csv_path}...")
        df = pd.read_csv(csv_path)
    else:
        print(f"[*] Dataset not found at {csv_path}. Generating benchmark network log dataset...")
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        df = generate_synthetic_cyber_dataset(n_samples=12000)
        df.to_csv(csv_path, index=False)
        print(f"[+] Successfully generated and saved {len(df)} samples to {csv_path}")
    return df


if __name__ == "__main__":
    dataset = load_or_create_dataset()
    print("Dataset Summary:")
    print(dataset["attack_type"].value_counts())
    print(dataset.head(3))
