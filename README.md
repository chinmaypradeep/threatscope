# ThreatScope 🎯
**Live Network Threat Intelligence Dashboard**

ThreatScope is a production-ready, real-time Network Intrusion Detection System (IDS). It captures live network packets, extracts CICIDS2018-compliant flow features, predicts anomalies using a trained Random Forest model, and instantly visualizes the threats on a beautiful dark-mode React dashboard using WebSockets and Redis.

![ThreatScope Architecture](https://img.shields.io/badge/Architecture-Microservices-blue)
![Python](https://img.shields.io/badge/Python-3.14-blue)
![React](https://img.shields.io/badge/React-19-cyan)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![Redis](https://img.shields.io/badge/Redis-Docker-red)

---

## 🏗️ Architecture

ThreatScope is built using a modern, decoupled microservices architecture:

1. **Packet Sniffer (`src/live_sniffer.py`)**: Uses `PyShark` to capture live traffic from your network interface (e.g., `en0`), groups packets into flows, extracts statistical features, and publishes them to a Redis stream.
2. **Message Broker (`Redis`)**: Acts as a high-throughput buffer to handle sudden bursts of network traffic, preventing the ML API from being overwhelmed.
3. **Intelligence Engine (`src/api.py`)**: A FastAPI backend that continuously consumes the Redis stream. It feeds network features into a Random Forest model. If an attack is detected, it generates explainability metrics via `SHAP` and performs GeoIP lookups.
4. **Real-time Dashboard (`frontend/`)**: A Vite/React application that connects to the FastAPI backend via WebSockets. It instantly renders anomalies on a glowing world map and displays SHAP feature insights.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.14+
- Node.js (for the frontend)
- Docker (for Redis)
- Npcap / Wireshark installed (required by PyShark)

### 2. Start Redis
Start the Redis message broker using Docker Compose:
```bash
docker-compose up -d
```

### 3. Start the Intelligence Engine (FastAPI)
Open a terminal, activate your virtual environment, and run the backend:
```bash
source venv/bin/activate
pip install -r requirements.txt
uvicorn src.api:app --reload
```

### 4. Start the Live Sniffer
Open a *new* terminal. The sniffer requires `sudo` privileges to capture live network traffic from your interface:
```bash
source venv/bin/activate
sudo python src/live_sniffer.py
```
*(Note: If your active interface is not `en0`, update the `INTERFACE` variable in `src/live_sniffer.py`)*

### 5. Launch the Dashboard
Open a third terminal, install the frontend dependencies, and start the Vite dev server:
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:5173` to view the live dashboard!

---

## 🧠 Explainable AI (XAI)
ThreatScope doesn't just tell you there is an attack; it tells you *why*. Using **SHAP (SHapley Additive exPlanations)**, the dashboard breaks down the exact network features (e.g., abnormally large packet sizes or irregular inter-arrival times) that caused the Random Forest model to flag the flow as anomalous.

## 📦 File Structure

```
ThreatScope/
├── src/
│   ├── api.py                      # FastAPI Backend & ML Inference
│   ├── live_sniffer.py             # PyShark Live Capture Engine
│   └── pcap_feature_extractor.py   # CICIDS2018 Feature Engineering
├── frontend/                       # React / Vite Dashboard
│   ├── src/
│   │   ├── App.jsx                 # Main Dashboard Layout
│   │   └── index.css               # Dark-mode Glassmorphism UI
├── models/
│   └── random_forest_model.pkl     # Pre-trained ML Model
├── docker-compose.yml              # Redis Container Config
└── requirements.txt                # Python Dependencies
```

## 📝 License
MIT License
