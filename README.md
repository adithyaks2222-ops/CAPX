# CAPX - Cyber Analysis & Protection eXplorer

**CAPX** is a Windows endpoint analysis, system-health, and internal defense software[cite: 1]. It analyzes a Windows computer to identify system-performance problems, resource-heavy processes, suspicious behavior, network activity, and persistence indicators[cite: 1]. It provides risk assessments, findings, and safe user-approved optimization actions[cite: 1].

## 🛡️ Core Operating Modes

CAPX is designed around three primary operating modes[cite: 1]:
* **Inspect (`capx inspect`)**: Full system and security analysis[cite: 1].
* **Monitor (`capx monitor`)**: Continuous monitoring of system and security indicators[cite: 1]. *(In Development)*
* **Optimize (`capx optimize`)**: Guided performance optimization and cleanup[cite: 1]. *(In Development)*

## 🏗️ Architecture & Security Principles

CAPX is built as serious security software, prioritizing correctness, safety, and maintainability[cite: 1]. It enforces a strict separation of concerns to ensure data integrity:

1. **Collectors**: Interface directly with the Windows OS to gather raw facts (Processes, Network, Startup, System). Collectors *never* contain cybersecurity logic.
2. **Analysis Layer**: Interprets collected facts without automatically declaring a process malicious[cite: 1].
3. **Detection Engine**: Correlates indicators across multiple domains to identify multi-vector behavioral anomalies[cite: 1].
4. **Risk Engine**: Produces a structured risk score and confidence information[cite: 1].
5. **API & UI**: The CLI (and future Flask UI) handles presentation strictly via the internal API. It contains zero cybersecurity logic.

**Safety Principle:** CAPX does not automatically terminate unknown processes, delete system-critical files, or classify high-resource processes as security threats without user confirmation[cite: 1].

## 🚀 Installation

Ensure you have **Python 3.8+** installed on your Windows machine.

1. Clone the repository:
   ```cmd
   git clone [https://github.com/adithyaks2222-ops/CAPX.git](https://github.com/adithyaks2222-ops/CAPX.git)
   cd CAPX
