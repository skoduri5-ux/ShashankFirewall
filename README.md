# 🛡️ ShashFirewall v2

A Python-based **Stateful Firewall & Intrusion Prevention System (IPS)** that combines **Packet Filtering (ACL)** and **Stateful Inspection** to detect and mitigate common network attacks in real time.

---

## 🚀 Features

### 🔵 Packet Filtering (Stateless Engine)

* Access Control List (ACL) rule engine
* Source/Destination IP filtering
* Port filtering
* Protocol filtering (TCP, UDP, ICMP)
* First-match rule evaluation
* Unmatched traffic logging

### 🟣 Stateful Inspection Engine

* TCP connection tracking
* Full TCP state machine

  * SYN_SENT
  * SYN_RCVD
  * ESTABLISHED
  * FIN_WAIT
  * CLOSED
* Connection timeout handling
* Detection of invalid state transitions

---

## 🛡️ Attack Detection

* Brute Force Detection
* ICMP Flood Detection
* SYN Flood Detection
* Half-open Connection Detection
* Out-of-State TCP Packet Detection

---

## ⚔️ Countermeasures

When an attack is detected, the firewall can automatically:

* Block attacker IP using Linux iptables
* Deploy TCP RST Volley
* Deploy Tarpit
* Log attack details
* Display alerts on the dashboard

---

## 📊 Dashboard

Real-time Flask dashboard displaying:

* Total Packets
* ACL Denied Packets
* Stateful Denied Packets
* Detected Attacks
* Blocked IP Addresses
* Live Event Feed
* TCP Connection Table

---

## 🏗️ Project Architecture

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
 └── Tarpit
        │
        ▼
Dashboard & Logs
```

---

## 🧰 Technologies Used

* Python 3
* Scapy
* Flask
* Linux iptables
* Threading
* Socket Programming

---

## 📂 Project Structure

```
ShashFirewall/
│
├── firewall_v2.py
├── test_firewall_v2.py
├── requirements.txt
├── README.md
├── .gitignore
└── screenshots/
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/ShashankFirewall.git
cd ShashankFirewall
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Run

```bash
sudo ./venv/bin/python firewall_v2.py --iface eth0
```

Dashboard:

```
http://localhost:5000
```

---

## 🧪 Testing

### ICMP Flood

```bash
sudo ping -f 8.8.8.8
```

### Brute Force Simulation

```bash
for i in {1..10}; do
    nc -vz <target-ip> 8080
done
```

---

## 📸 Screenshots

Add screenshots such as:

* Dashboard
* Connection Table
* Attack Detection
* Blocked IPs
* iptables Rules
* Live Event Feed

---

## 📈 Future Improvements

* IPv6 Support
* Geo-IP Blocking
* Web-based Rule Management
* Email Alerts
* SQLite Logging
* ML-based Anomaly Detection
* Rule Import/Export

---

## 👨‍💻 Author

**Shashank Koduri**

* GitHub: https://github.com/skoduri5-ux

---

## 📜 License

This project is released under the MIT License.
