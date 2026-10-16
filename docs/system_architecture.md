# System Architecture Specification: AI-Powered Cyber Threat Detection

## 1. Threat Landscape & Problem Definition
Enterprise networks process gigabits of ingress and egress traffic per second. Attackers employ:
- **Volumetric Attacks**: SYN flood denial of service that exhausts TCP socket state buffers.
- **Reconnaissance Attacks**: Distributed port scans scanning for open services (`diff_srv_rate` spikes).
- **Authentication Cracking**: High-velocity SSH/RDP dictionary attacks.
- **Data Exfiltration**: Stealthy long-duration outbound connections with oversized payloads.

## 2. Hybrid Defense Layer
```
                                 Raw Packet Log
                                       │
                         ┌─────────────┴─────────────┐
                         ▼                           ▼
                 Random Forest               Isolation Forest
              (Known Attack Patterns)       (Zero-Day Anomalies)
                         │                           │
                         │ P(Threat)                 │ Decision Score
                         └─────────────┬─────────────┘
                                       │
                                       ▼
                             Risk Scoring Engine
                       Composite Score = 0.65*RF + 0.35*Iso
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
              Score >= 60 (Alert)               Score < 60 (Benign)
                      │                                 │
              SOC Alert + Mitigation                    Allow Traffic
```

## 3. Mathematical Formulations

### 3.1 Random Forest Gini Impurity
$$Gini(D) = 1 - \sum_{i=1}^{C} p_i^2$$

### 3.2 Isolation Forest Path Length
Anomaly score $s(x, n)$:
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
where $h(x)$ is path length and $c(n)$ is average path length of unsuccessful search in BST:
$$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n-1)}{n}$$

### 3.3 Composite Risk Score
$$\text{RiskScore} = \text{clamp}\left(65 \cdot P_{\text{RF}}(\text{threat}) + 35 \cdot \max(0, \min(1, 0.5 - s_{\text{iso}})), 0, 100\right)$$
