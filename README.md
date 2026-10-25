# EmailGuard - Email Spam & Duplicate ("Same") Detector

A modern full-stack Python application featuring a dual-engine architecture:
1. **Email Spam & Phishing Detector**: Machine Learning (TF-IDF + Multinomial Naive Bayes + Heuristic Threat Analysis) to evaluate spam probability, security risk levels, and trigger keywords.
2. **Email Duplicate & "Same Email" Detector**: Text similarity engine (Cosine Similarity, Jaccard Index, and Sequence Alignment) to detect identical clones, paraphrased duplicates, and compare emails against a template database.

---

## 🚀 Features

- **Interactive Modern Web Dashboard**: Responsive single-page interface with tabbed views, animated score gauges, risk badges, and one-click demo samples.
- **Dual-Capability Core Engine**:
  - **Spam Classification**: Detects phishing scams, lottery fraud, crypto spam, fake invoices, and urgent threats.
  - **Duplicate ("Same") Detection**: Compares two emails side-by-side or searches an email database for existing duplicates.
- **RESTful API**: Easily integrate with other services, mobile apps, or security automation pipelines.
- **Zero-Crash Resilience**: Auto-trains model on initial startup if not present, with pure-Python fallbacks.
- **Batch Processing**: Analyze multiple emails in a single request.
- **Automated Test Suite**: Comprehensive unit and integration tests.

---

## 📁 Project Structure

```
email-detector-app/
│
├── app.py                      # Flask web server and REST API endpoints
├── model.py                    # Dual-engine detector (Spam ML + Similarity engine)
├── train.py                    # Script to train/evaluate and export model.pkl
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── data/
│   ├── sample_emails.csv       # Preloaded dataset of 30+ labeled spam/ham emails
│   └── model.pkl               # Persisted trained scikit-learn model
│
├── static/
│   ├── css/
│   │   └── style.css           # Modern CSS styling (cards, badges, gauges, tables)
│   └── js/
│       └── app.js              # Asynchronous API client, sample loaders, UI logic
│
├── templates/
│   └── index.html              # Frontend single-page application dashboard
│
└── tests/
    └── test_app.py             # Automated unit tests for ML, algorithms & APIs
```

---

## ⚡ Quick Start

### 1. Install Dependencies
Make sure you have Python 3.9+ installed. Then install the required packages:

```bash
pip install -r requirements.txt
```

### 2. Run the Application
Start the Flask server:

```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧠 Retraining the Model

You can add more training data to `data/sample_emails.csv` and retrain the classifier anytime:

```bash
python train.py
```

This outputs validation metrics (accuracy, precision, recall, F1-score) and exports the updated `data/model.pkl`.

---

## 🧪 Running Automated Tests

Run the test suite to verify model predictions and API endpoints:

```bash
python -m unittest tests/test_app.py
```

---

## 🔌 REST API Reference

### 1. Detect Spam
- **Endpoint**: `POST /api/detect-spam`
- **Request Body**:
```json
{
  "subject": "URGENT: Your account has been suspended!",
  "body": "Click here immediately to verify your bank credentials."
}
```
- **Response**:
```json
{
  "success": true,
  "data": {
    "label": "SPAM",
    "is_spam": true,
    "spam_probability": 85.5,
    "ham_probability": 14.5,
    "risk_level": "Dangerous",
    "confidence": 85.5,
    "trigger_words": [
      { "keyword": "urgent", "count": 1 },
      { "keyword": "suspended", "count": 1 },
      { "keyword": "verify your credentials", "count": 1 }
    ],
    "explanation": "Flagged as SPAM due to detected threat patterns and urgency triggers."
  }
}
```

### 2. Check Similarity / Same Email
- **Endpoint**: `POST /api/check-similarity`
- **Request Body**:
```json
{
  "email1": "Notice: Server maintenance scheduled for Saturday 01:00 UTC.",
  "email2": "Notice: Planned server maintenance scheduled for Saturday 01:00 UTC."
}
```
- **Response**:
```json
{
  "success": true,
  "data": {
    "similarity_percentage": 88.4,
    "is_same": true,
    "match_type": "Duplicate / Highly Similar",
    "summary": "The emails share almost all key wording and structure.",
    "metrics": {
      "cosine_similarity": 0.912,
      "jaccard_similarity": 0.815,
      "character_ratio": 0.924
    }
  }
}
```

### 3. Check Against Database Library
- **Endpoint**: `POST /api/check-library`
- **Request Body**:
```json
{
  "email": "Upcoming scheduled downtime for production servers this weekend."
}
```

### 4. Health Check
- **Endpoint**: `GET /api/health`
- **Response**:
```json
{
  "status": "healthy",
  "model_trained": true,
  "scikit_learn_available": true,
  "version": "1.0.0"
}
```

---

## 📄 License
MIT License. Free to use and modify for personal and educational projects.
