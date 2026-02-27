# PhishGuard-AI-driven-Phishing-Detection-System

**Project Description:**  
**PhishGuard** is a comprehensive, AI-powered phishing detection system designed to safeguard users from phishing attacks across multiple channels including **Email, SMS, URLs, and QR codes**. With the growing sophistication of phishing attempts, this system leverages **machine learning, feature engineering, and computer vision** to identify malicious content in real-time, providing actionable alerts and enhancing cybersecurity awareness.

The system extracts key features from text and URLs, such as **entropy, tokenization, subdomains, HTTPS presence, suspicious file extensions, and numeric characters**, to train ML models that classify messages and links as **SAFE** or **PHISHING**. Additionally, QR code content is decoded using **OpenCV**, enabling both **image uploads** and **real-time camera scanning** for instant threat detection.

---

## Key Features
- Detects phishing in **Email and SMS** using trained AI models.
- Identifies **malicious URLs** through advanced feature analysis.
- Supports **QR code scanning** with real-time camera detection.
- Interactive **Streamlit web interface** with clear SAFE/PHISHING alerts.
- Offline detection ensures **user privacy** without relying on external APIs.
- Modular architecture for easy integration with larger security systems.

---

## Objective
Provide a **user-friendly, end-to-end phishing detection solution** combining real-time scanning, AI-driven insights, and multi-channel protection to prevent financial loss and information theft.

---

## Target Audience / Use Cases
- Individuals verifying emails, messages, URLs, or QR codes.
- Organizations implementing internal phishing detection tools for employees.
- Developers seeking an AI-based phishing detection framework for integration.

---

## Technology Stack
- **Programming Language:** Python  
- **ML & Data Processing:** scikit-learn, NumPy, Pandas, re  
- **Computer Vision:** OpenCV  
- **Web Interface:** Streamlit  
- **Other:** Pickle (model serialization)

---

## Project Structure
PhishGuard/
│
├─ app.py # Main Streamlit application
├─ text_fraud_model.pkl # ML model for text detection
├─ text_vectorizer.pkl # Vectorizer for text preprocessing
├─ url_fraud_model.pkl # ML model for URL detection
├─ requirements.txt # Python dependencies
└─ README.md # Project documentation


