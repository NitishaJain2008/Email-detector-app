"""
Flask Application for Email Detector (Spam & Duplicate/Same Detector).
Serves the web dashboard and REST API endpoints.
"""

import os
from flask import Flask, render_template, request, jsonify
from model import EmailDetector

app = Flask(__name__, static_folder="static", template_folder="templates")

# Initialize global detector instance
detector = EmailDetector()

# Sample stored email library for duplicate/same detection lookup
DEFAULT_EMAIL_LIBRARY = [
    {
        "id": "LIB-001",
        "subject": "Quarterly Performance Review Schedule",
        "body": "Dear team member, your annual and quarterly performance review has been scheduled for next Wednesday at 2 PM. Please submit your self-assessment form before Monday."
    },
    {
        "id": "LIB-002",
        "subject": "System Maintenance Downtime Notice",
        "body": "Notice: Our internal production servers will undergo scheduled infrastructure maintenance this Saturday between 01:00 UTC and 04:00 UTC. Services will be briefly unavailable."
    },
    {
        "id": "LIB-003",
        "subject": "Security Warning: Suspicious Login Detected",
        "body": "We detected an unfamiliar sign-in attempt to your account from IP address 192.168.1.1. If this was not you, please secure your account immediately."
    },
    {
        "id": "LIB-004",
        "subject": "Invoice #49281 Settlement Confirmation",
        "body": "Thank you for your recent wire payment. Invoice #49281 in the amount of $1,250.00 has been marked as fully settled in our accounting system."
    }
]


@app.route("/")
def index():
    """Render the main single-page web dashboard."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "model_trained": detector.is_trained,
        "scikit_learn_available": detector.pipeline is not None,
        "version": "1.0.0"
    })


@app.route("/api/detect-spam", methods=["POST"])
def detect_spam():
    """
    Classify an email as SPAM or HAM.
    Expected JSON: { "subject": str (optional), "body": str }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        body = data.get("body", "").strip()
        subject = data.get("subject", "").strip()

        if not body and not subject:
            return jsonify({
                "success": False,
                "error": "Please provide an email subject or body text."
            }), 400

        result = detector.predict_spam(text=body, subject=subject)
        return jsonify({
            "success": True,
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/check-similarity", methods=["POST"])
def check_similarity():
    """
    Compare two emails to detect whether they are identical, duplicates, or similar.
    Expected JSON: { "email1": str, "email2": str }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        email1 = data.get("email1", "").strip()
        email2 = data.get("email2", "").strip()

        if not email1 or not email2:
            return jsonify({
                "success": False,
                "error": "Please provide both 'email1' and 'email2' to compare."
            }), 400

        result = detector.calculate_similarity(email1, email2)
        return jsonify({
            "success": True,
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/check-library", methods=["POST"])
def check_library():
    """
    Check an email against stored email templates in the library to find duplicate matches.
    Expected JSON: { "email": str, "library": list (optional) }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        email_text = data.get("email", "").strip()
        custom_library = data.get("library", None)

        if not email_text:
            return jsonify({
                "success": False,
                "error": "Please provide email text to inspect."
            }), 400

        target_lib = custom_library if isinstance(custom_library, list) and custom_library else DEFAULT_EMAIL_LIBRARY
        result = detector.check_duplicate_in_library(email_text, target_lib)

        return jsonify({
            "success": True,
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/batch-detect", methods=["POST"])
def batch_detect():
    """
    Batch evaluate a list of emails for both spam and duplicates.
    Expected JSON: { "emails": [ { "id": "1", "subject": "...", "body": "..." }, ... ] }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        emails = data.get("emails", [])

        if not isinstance(emails, list) or not emails:
            return jsonify({
                "success": False,
                "error": "Please provide a non-empty array of email objects."
            }), 400

        analyzed = []
        for idx, item in enumerate(emails):
            subj = item.get("subject", "")
            body = item.get("body", "")
            item_id = item.get("id", f"Email-{idx + 1}")

            spam_res = detector.predict_spam(body, subject=subj)

            analyzed.append({
                "id": item_id,
                "subject": subj,
                "label": spam_res["label"],
                "spam_probability": spam_res["spam_probability"],
                "risk_level": spam_res["risk_level"],
                "trigger_words": [t["keyword"] for t in spam_res["trigger_words"]],
                "explanation": spam_res["explanation"]
            })

        return jsonify({
            "success": True,
            "count": len(analyzed),
            "data": analyzed
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/sample-data", methods=["GET"])
def sample_data():
    """Return preset samples for quick UI demonstration."""
    return jsonify({
        "spam_samples": [
            {
                "title": "Phishing / Security Scam",
                "subject": "URGENT: Your account has been suspended!",
                "body": "Dear customer, we detected unauthorized attempts to access your bank account. You must verify your credentials immediately by clicking here: http://secure-banking-login-auth.com or your account will be permanently closed within 24 hours."
            },
            {
                "title": "Lottery / Prize Fraud",
                "subject": "CONGRATULATIONS! You won $2,500,000.00!",
                "body": "You have been selected as the grand prize lucky winner of the International Powerball Sweepstakes 2026! Reply with your full legal name, home address, and phone number to claim your instant cash wire transfer."
            },
            {
                "title": "Crypto / Get Rich Quick",
                "subject": "Make $5,000 weekly working from home easily!",
                "body": "Start earning passive income today with our automated crypto trading algorithm! No experience required, guaranteed 100% daily returns. Invest $100 today and watch your wallet grow. Sign up now."
            }
        ],
        "ham_samples": [
            {
                "title": "Work Sprint Planning",
                "subject": "Project roadmap discussion and sprint planning meeting",
                "body": "Hi team, I would like to schedule our quarterly sprint planning session for next Tuesday at 10:00 AM. Please review the updated product backlog on Jira and come prepared with your sprint estimates."
            },
            {
                "title": "Casual Friend Lunch",
                "subject": "Lunch plans this Friday afternoon?",
                "body": "Hey Sarah, are you free to grab lunch this Friday around 12:30 PM? There is a new ramen place down the street from the office that looks amazing. Let me know if that time works for you!"
            },
            {
                "title": "Order Confirmation",
                "subject": "Your Amazon order #112-9837162 has been shipped",
                "body": "Thank you for your order. Your package containing 'Python Programming: An Introduction to Computer Science' has shipped via UPS and is estimated to arrive on Thursday. Track your package in your account."
            }
        ],
        "similarity_pairs": [
            {
                "title": "Near Duplicate / Slight Rewrite",
                "email1": "Notice: Our internal production servers will undergo scheduled infrastructure maintenance this Saturday between 01:00 UTC and 04:00 UTC. Services will be briefly unavailable.",
                "email2": "Notice: Our primary production servers will undergo planned infrastructure maintenance this Saturday from 01:00 UTC to 04:00 UTC. Systems will be temporarily unavailable."
            },
            {
                "title": "Exact Identical Match",
                "email1": "Dear resident, your current residential lease agreement is scheduled to end on December 31. We would love to have you stay with us! Please review the attached renewal options.",
                "email2": "Dear resident, your current residential lease agreement is scheduled to end on December 31. We would love to have you stay with us! Please review the attached renewal options."
            },
            {
                "title": "Completely Different Emails",
                "email1": "Hey Sarah, are you free to grab lunch this Friday around 12:30 PM? There is a new ramen place down the street.",
                "email2": "URGENT: Your account has been suspended! Verify your credentials immediately by clicking here to prevent closure."
            }
        ]
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Email Detector server on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
