# 🛡️ VulnScanner AI

An AI-powered Web Vulnerability Scanner that automates security assessment by combining traditional vulnerability scanning techniques with Machine Learning and Large Language Models (LLMs). The application crawls web pages, performs payload-based security testing, detects common web vulnerabilities, and provides AI-generated explanations with remediation guidance.

## 🚀 Features

- 🔍 Automated Website Crawling
- 💉 SQL Injection Detection
- ⚡ Reflected XSS Detection
- 🤖 Machine Learning-based Vulnerability Classification
- 🧠 LLM-powered Vulnerability Explanation (Meta Llama 3.1)
- 📊 Vulnerability Confidence Score
- 🌐 Modern Interactive Dashboard
- 📄 Real-time Scan Results
- 🎯 Educational Security Research Tool

---

## 🏗️ Tech Stack

### Backend
- Python
- Flask

### Frontend
- HTML5
- CSS3
- JavaScript

### Machine Learning
- Scikit-learn
- Random Forest Classifier
- TF-IDF Vectorizer
- Pandas
- NumPy

### AI
- Meta Llama 3.1 (SambaNova API)

### Security Modules
- SQL Injection Scanner
- Cross Site Scripting (XSS) Scanner
- Prompt Injection Detection
- Data Leakage Detection

### Libraries
- BeautifulSoup
- Requests
- Joblib
- LXML

---

## 📂 Project Structure

```
ai-vuln-scanner/
│
├── app/
│   ├── crawler.py
│   ├── injector.py
│   ├── model.py
│   ├── routes.py
│   ├── train.py
│   ├── dataset.py
│   ├── llm_explainer.py
│   └── __init__.py
│
├── static/
│
├── run.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/yourusername/ai-vuln-scanner.git
```

Navigate into the project

```bash
cd ai-vuln-scanner
```

Create virtual environment

```bash
python -m venv venv
```

Activate virtual environment

Windows

```bash
venv\Scripts\activate
```

Linux / Mac

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python run.py
```

Open

```
http://localhost:8080
```

---

## 🧠 How It Works

1. Crawl the target website
2. Identify forms and endpoints
3. Inject security payloads
4. Analyze server responses
5. Detect vulnerabilities using ML and rule-based analysis
6. Generate AI-powered remediation suggestions

---

## 📌 Disclaimer

This project is intended **only for educational purposes and authorized security testing**. Do not scan systems without proper authorization.

---

## 👨‍💻 Author

Ayush Ojha