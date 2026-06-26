# 🛡️ ShashFirewall v2

A Python-based **Stateful Firewall & Intrusion Prevention System (IPS)** that combines **Packet Filtering (ACL)** and **Stateful Inspection** to monitor, detect, and mitigate common network attacks in real time using **Scapy**, **Flask**, and **Linux iptables**.

---

# 🚀 Features

## 🔵 Packet Filtering Engine (Stateless)

* Access Control List (ACL) Rule Engine
* Source IP Filtering
* Destination IP Filtering
* TCP/UDP/ICMP Protocol Filtering
* Port-based Filtering
* First-Match Rule Evaluation
* Unmatched Traffic Logging

---

## 🟣 Stateful Inspection Engine

Maintains a live TCP connection table by tracking the entire TCP lifecycle.

Supported TCP States:

* SYN_SENT
* SYN_RCVD
* ESTABLISHED
* FIN_WAIT
* CLOSED

Features:

* Stateful Connection Tracking
* Connection Timeout Cleanup
* Invalid State Detection
* Half-open Connection Monitoring

---

# 🛡️ Attack Detection

ShashFirewall can detect:

* SSH Brute Force
* TCP SYN Flood
* ICMP Flood
* Half-open Connection Flood
* Invalid TCP State Transitions
* Port Scanning (optional)

---

# ⚔️ Countermeasures

When malicious activity exceeds the configured threshold, the firewall can automatically:

* Block attacker IP using Linux iptables
* Send TCP RST Volley
* Deploy TCP Tarpit
* Log attack details
* Display alerts on the live dashboard

---

# 📊 Dashboard

The integrated Flask dashboard provides:

* Total Packets Processed
* ACL Denied Packets
* Stateful Denied Packets
* Attack Counter
* Live Event Feed
* Blocked IP List
* TCP Connection Table
* Firewall Statistics

Dashboard URL:

```
http://localhost:5000
```

---

# 🏗️ Architecture

```
Incoming Packet
        │
        ▼
Packet Filtering Engine (ACL)
        │
        ▼
Stateful Inspection Engine
        │
        ▼
Attack Detection
        │
        ▼
Countermeasures
 ├── iptables Block
 ├── TCP RST Volley
 └── TCP Tarpit
        │
        ▼
Dashboard & Logs
```

---

# 🧰 Technologies Used

* Python 3
* Scapy
* Flask
* Linux iptables
* Socket Programming
* Threading
* Docker
* Docker Compose

---

# 📂 Project Structure

```
ShashFirewall/
│
├── firewall_v2.py
├── test_firewall_v2.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── README.md
├── screenshots/
└── .gitignore
```

---

# 💻 Requirements

* Ubuntu / Debian / Kali Linux
* Python 3.10+
* Root Privileges
* Linux iptables
* Git

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/skoduri5-ux/ShashankFirewall.git
cd ShashankFirewall
```

---

## Install System Packages

Ubuntu / Debian:

```bash
sudo apt update

sudo apt install -y \
python3 \
python3-pip \
python3-venv \
python3-dev \
iptables \
tcpdump \
iproute2 \
git
```

---

## Create Virtual Environment

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## Install Python Dependencies

```bash
pip install --upgrade pip

pip install -r requirements.txt
```

---

# ▶️ Running the Firewall

```bash
sudo ./venv/bin/python firewall_v2.py --iface eth0
```

or

```bash
sudo python3 firewall_v2.py --iface eth0
```

---

# 🐳 Docker Deployment

## Build

```bash
docker compose build
```

or

```bash
docker build -t shashfirewall .
```

## Run

```bash
docker compose up
```

or

```bash
docker run \
--network host \
--cap-add NET_ADMIN \
--cap-add NET_RAW \
shashfirewall
```

---

# 🧪 Testing

## SSH Connection

```bash
ssh username@<target-ip>
```

---

## SSH Brute Force Simulation

```powershell
1..20 | % {
    Test-NetConnection <target-ip> -Port 22 | Out-Null
}
```

---

## HTTP Connection Test

```bash
python3 -m http.server 8080
```

Windows:

```powershell
Test-NetConnection <target-ip> -Port 8080
```

---

## ICMP Flood

```bash
sudo ping -f <target-ip>
```

---

# 📸 Screenshots

Include screenshots of:

* Dashboard
* Stateful Connection Table
* Attack Detection
* Blocked IP List
* iptables Rules
* Docker Deployment
* Live Event Feed

---

# 📈 Future Improvements

* IPv6 Support
* Geo-IP Blocking
* SQLite Logging
* Email Alerts
* Rule Management UI
* ML-based Anomaly Detection
* Rule Import/Export
* Prometheus Metrics
* Grafana Dashboard

---

# 👨‍💻 Author

**Shashank Koduri**

GitHub:

https://github.com/skoduri5-ux

---

# 📜 License

Released under the MIT License.
