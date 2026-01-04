# 🛡️ CyberSentinel

CyberSentinel is a comprehensive cybersecurity dashboard and utility tool built with **Streamlit**. It is designed to provide users with a centralized interface for vulnerability scanning, security auditing, and real-time threat analysis.

## 🚀 Live Demo
Check out the live app here: [cybersentinel-beta on Streamlit](https://cybersentinel-beta.streamlit.app/)

## ✨ Key Features
- **Vulnerability Scanner:** Detect common web vulnerabilities like SQL Injection, XSS, and CSRF.
- **CVE Lookup:** Search and retrieve detailed information from the National Vulnerability Database (NVD).
- **Network Security:** Basic tools for port scanning and server vulnerability assessment.
- **Security Insights:** A real-time dashboard displaying common cybersecurity incidents, risk levels, and mitigation tips.
- **AI-Powered Assistance:** Integration with AI models to answer complex cybersecurity queries.

## 🛠️ Tech Stack
- **Frontend/Hosting:** Streamlit
- **Backend:** Python
- **APIs:** NVD (CVE API)
- **Libraries:** Pandas, Requests, BeautifulSoup4, Scapy

## 📂 Project Structure
```text
├── app.py                # Main Streamlit application
├── scanners/             # Modules for different security tests
├── data/                 # Sample logs or security datasets
├── utils/                # Helper functions for API calls
├── requirements.txt      # Python dependencies
└── README.md             # Documentation
