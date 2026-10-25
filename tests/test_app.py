"""
Automated Unit and Integration Tests for Email Detector application.
Verifies spam detection model, duplicate/same similarity algorithm, and Flask REST APIs.
"""

import unittest
import json
from model import EmailDetector
from app import app


class TestEmailDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = EmailDetector()
        cls.client = app.test_client()

    # 1. Spam Detection Unit Tests
    def test_phishing_spam_detection(self):
        sample = "URGENT: Your bank account has been suspended! Verify your credentials immediately by clicking here."
        res = self.detector.predict_spam(sample)
        self.assertEqual(res["label"], "SPAM")
        self.assertTrue(res["is_spam"])
        self.assertGreaterEqual(res["spam_probability"], 50.0)
        self.assertIn(res["risk_level"], ["High Risk", "Dangerous"])

    def test_lottery_scam_detection(self):
        sample = "CONGRATULATIONS! You won $2,500,000.00 cash sweepstakes! Claim your wire transfer."
        res = self.detector.predict_spam(sample)
        self.assertEqual(res["label"], "SPAM")
        self.assertTrue(res["is_spam"])
        self.assertGreaterEqual(res["spam_probability"], 50.0)

    def test_legitimate_ham_detection(self):
        sample = "Hi Sarah, are you free for lunch tomorrow at 12:30 PM? Let me know if that works."
        res = self.detector.predict_spam(sample)
        self.assertEqual(res["label"], "HAM")
        self.assertFalse(res["is_spam"])
        self.assertLess(res["spam_probability"], 50.0)

    # 2. Similarity & Duplicate ("Same") Unit Tests
    def test_identical_emails_similarity(self):
        email = "Dear customer, your order #1234 has been processed and shipped via FedEx."
        res = self.detector.calculate_similarity(email, email)
        self.assertEqual(res["similarity_percentage"], 100.0)
        self.assertTrue(res["is_same"])
        self.assertIn("Identical", res["match_type"])

    def test_near_duplicate_emails(self):
        e1 = "Internal production servers will undergo scheduled maintenance this Saturday between 01:00 UTC and 04:00 UTC."
        e2 = "Our primary production servers will undergo scheduled maintenance this Saturday from 01:00 UTC to 04:00 UTC."
        res = self.detector.calculate_similarity(e1, e2)
        self.assertGreaterEqual(res["similarity_percentage"], 75.0)

    def test_distinct_different_emails(self):
        e1 = "Quarterly financial budget forecast is attached for team review."
        e2 = "Buy discount medication and prescription pills online with free express shipping."
        res = self.detector.calculate_similarity(e1, e2)
        self.assertLess(res["similarity_percentage"], 50.0)
        self.assertFalse(res["is_same"])

    # 3. Flask REST API Integration Tests
    def test_health_api(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_trained"])

    def test_detect_spam_api(self):
        payload = {
            "subject": "Pre-approved loan offer",
            "body": "Get approved for a fast cash loan today with zero interest and instant wire transfer!"
        }
        resp = self.client.post("/api/detect-spam", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["label"], "SPAM")

    def test_check_similarity_api(self):
        payload = {
            "email1": "Meeting tomorrow at 9 AM in Conference Room B.",
            "email2": "Meeting tomorrow at 9 AM in Conference Room B."
        }
        resp = self.client.post("/api/check-similarity", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["similarity_percentage"], 100.0)
        self.assertTrue(data["data"]["is_same"])

    def test_batch_detect_api(self):
        payload = {
            "emails": [
                {"id": "E1", "subject": "Work update", "body": "Sprint progress is on track for Friday."},
                {"id": "E2", "subject": "Claim prize", "body": "You won the international lottery, reply now!"}
            ]
        }
        resp = self.client.post("/api/batch-detect", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertEqual(len(data["data"]), 2)


if __name__ == "__main__":
    unittest.main()
