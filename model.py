"""
Email Detector Model
Provides dual-capability NLP & ML engines:
1. Email Spam & Phishing Classification (TF-IDF + Multinomial Naive Bayes & heuristic indicators)
2. Email Similarity & Duplicate ("Same") Detection (Cosine similarity, Jaccard overlap, and Levenshtein metrics)
"""

import os
import re
import math
import difflib
from typing import Dict, List, Any, Tuple

# Try to import scikit-learn & joblib, with automatic pure-Python fallback
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    from sklearn.metrics.pairwise import cosine_similarity
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Known high-confidence spam / phishing trigger terms
SPAM_TRIGGERS = [
    "urgent", "suspended", "verify your credentials", "unauthorized",
    "wire transfer", "won", "winner", "congratulations", "sweepstakes",
    "lottery", "passive income", "crypto", "free gift card", "bitcoin",
    "claim your", "100% free", "guaranteed", "pre-approved", "loan",
    "viagra", "cialis", "prescription", "cheap meds", "past due invoice",
    "overdue", "remit payment", "direct deposit", "unclaimed balance",
    "act now", "limited time offer", "click here", "dating matches",
    "tax refund", "rebate", "luxury replica", "rolex", "fast cash",
    "confidential estate", "risk-free", "double your money"
]


class EmailDetector:
    def __init__(self, model_path: str = None, dataset_path: str = None):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = model_path or os.path.join(self.base_dir, "data", "model.pkl")
        self.dataset_path = dataset_path or os.path.join(self.base_dir, "data", "sample_emails.csv")
        self.pipeline = None
        self.is_trained = False
        
        # Load or train model
        self.initialize_model()

    def preprocess_text(self, text: str) -> str:
        """Clean and normalize email text."""
        if not text:
            return ""
        # Lowercase
        text = text.lower()
        # Replace URLs with token
        text = re.sub(r'https?://\S+|www\.\S+', ' url_link ', text)
        # Replace numbers / money amounts with token
        text = re.sub(r'\$\d+(?:,\d+)*(?:\.\d+)?|\b\d+\b', ' num_val ', text)
        # Remove non-word characters except whitespace
        text = re.sub(r'[^\w\s]', ' ', text)
        # Collapse multiple spaces
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def initialize_model(self):
        """Load trained pipeline from disk or auto-train from sample dataset."""
        if HAS_SKLEARN and os.path.exists(self.model_path):
            try:
                self.pipeline = joblib.load(self.model_path)
                self.is_trained = True
                return
            except Exception as e:
                print(f"Warning: Failed to load existing model from {self.model_path}: {e}")

        # If model doesn't exist, try auto-training from CSV
        if HAS_SKLEARN and os.path.exists(self.dataset_path):
            self.train_from_csv(self.dataset_path)
        else:
            self.is_trained = True  # Fallback engine is always available

    def train_from_csv(self, csv_path: str) -> bool:
        """Trains a TF-IDF + Naive Bayes pipeline on the CSV dataset."""
        if not HAS_SKLEARN:
            return False

        try:
            import pandas as pd
            df = pd.read_csv(csv_path)
            # Combine subject and body
            texts = (df['subject'].fillna('') + " " + df['body'].fillna('')).apply(self.preprocess_text).tolist()
            labels = df['label'].astype(int).tolist()

            self.pipeline = Pipeline([
                ('tfidf', TfidfVectorizer(ngram_range=(1, 2), min_df=1, stop_words='english')),
                ('clf', MultinomialNB(alpha=0.1))
            ])
            self.pipeline.fit(texts, labels)

            # Save model to disk
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.pipeline, self.model_path)
            self.is_trained = True
            return True
        except Exception as e:
            print(f"Error training model: {e}")
            return False

    def _fallback_spam_score(self, text: str) -> float:
        """Heuristic score between 0.0 and 1.0 when scikit-learn is not available."""
        lower_text = text.lower()
        score = 0.0
        # Trigger matches
        matched_count = sum(1 for trigger in SPAM_TRIGGERS if trigger in lower_text)
        score += min(matched_count * 0.22, 0.70)

        # Urgent / Capital letters check
        caps = sum(1 for c in text if c.isupper())
        total_chars = max(len(text), 1)
        if caps / total_chars > 0.35 and total_chars > 20:
            score += 0.20

        # Excessive exclamation marks
        if text.count('!') >= 3:
            score += 0.15

        # Suspicious links
        if re.search(r'https?://|www\.|\.xyz|\.click|\.ru|\.top', lower_text):
            score += 0.15

        return min(max(score, 0.02), 0.98)

    def extract_heuristics(self, subject: str, body: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Detect heuristic red flags and matched spam triggers."""
        full_text = f"{subject} {body}"
        lower_text = full_text.lower()
        
        heuristics = []
        triggers_found = []

        # Find matching trigger keywords
        for trigger in SPAM_TRIGGERS:
            if trigger in lower_text:
                occurrences = len(re.findall(re.escape(trigger), lower_text))
                triggers_found.append({
                    "keyword": trigger,
                    "count": occurrences
                })

        # Excessive uppercase characters
        letters = [c for c in full_text if c.isalpha()]
        if letters:
            upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
            if upper_ratio > 0.35 and len(letters) > 15:
                heuristics.append(f"Excessive UPPERCASE text ({int(upper_ratio * 100)}% capital letters)")

        # Multiple exclamation / question marks
        exclamation_count = full_text.count('!')
        if exclamation_count >= 3:
            heuristics.append(f"Multiple exclamation marks ({exclamation_count} occurrences)")

        # URL / link analysis
        urls = re.findall(r'https?://\S+|www\.\S+', full_text)
        if urls:
            heuristics.append(f"Contains {len(urls)} external web link(s)")
            for u in urls:
                if re.search(r'(login|secure|verify|account|bank|claim|free|winner)', u.lower()):
                    heuristics.append(f"Suspicious URL wording in: {u[:45]}...")
                    break

        # Monetary urgency patterns
        if re.search(r'\$\s*\d+[\d,]*(\.\d+)?|\b\d+\s*(?:dollars|usd|million|grand)\b', lower_text):
            heuristics.append("Contains large monetary figures / cash amounts")

        if re.search(r'\b(within 24 hours|immediately|urgent|act now|hurry|final notice)\b', lower_text):
            heuristics.append("High urgency call-to-action detected")

        return heuristics, triggers_found

    def predict_spam(self, text: str, subject: str = "") -> Dict[str, Any]:
        """
        Classifies whether an email is SPAM or LEGITIMATE (HAM).
        Returns classification label, probability, risk level, triggers, and explanation.
        """
        raw_combined = f"{subject} {text}".strip()
        cleaned = self.preprocess_text(raw_combined)

        if not cleaned:
            return {
                "label": "HAM",
                "is_spam": False,
                "spam_probability": 0.0,
                "ham_probability": 100.0,
                "confidence": 100.0,
                "risk_level": "Safe",
                "risk_score": 0,
                "trigger_words": [],
                "heuristics": ["Empty email content"],
                "explanation": "No text content provided to evaluate."
            }

        # 1. ML Probability
        if HAS_SKLEARN and self.pipeline is not None:
            try:
                probs = self.pipeline.predict_proba([cleaned])[0]
                # classes_ usually [0, 1] for ham, spam
                classes = list(self.pipeline.classes_)
                spam_idx = classes.index(1) if 1 in classes else 1
                ham_idx = classes.index(0) if 0 in classes else 0
                ml_spam_prob = float(probs[spam_idx])
            except Exception:
                ml_spam_prob = self._fallback_spam_score(raw_combined)
        else:
            ml_spam_prob = self._fallback_spam_score(raw_combined)

        # 2. Heuristics & Keywords
        heuristics, triggers = self.extract_heuristics(subject, text)
        
        # Adjust score with heuristic triggers
        heuristic_boost = min(len(triggers) * 0.12 + len(heuristics) * 0.08, 0.40)
        final_spam_prob = min(max(ml_spam_prob * 0.70 + heuristic_boost * 0.30, 0.01), 0.99)
        
        # If strong triggers or URLs present, ensure it meets spam threshold
        if len(triggers) >= 2 or (len(triggers) >= 1 and len(heuristics) >= 2):
            final_spam_prob = max(final_spam_prob, 0.75)

        spam_percentage = round(final_spam_prob * 100, 2)
        ham_percentage = round((1.0 - final_spam_prob) * 100, 2)
        is_spam = final_spam_prob >= 0.50

        # Risk level determination
        if spam_percentage >= 80:
            risk_level = "Dangerous"
            label = "SPAM"
        elif spam_percentage >= 50:
            risk_level = "High Risk"
            label = "SPAM"
        elif spam_percentage >= 25:
            risk_level = "Suspicious"
            label = "HAM"
        else:
            risk_level = "Safe"
            label = "HAM"

        confidence = round(max(spam_percentage, ham_percentage), 2)

        # Build explanation
        if is_spam:
            if triggers:
                top_trig = ", ".join([f"'{t['keyword']}'" for t in triggers[:3]])
                explanation = f"Flagged as SPAM due to detected threat patterns ({top_trig}) and {len(heuristics)} heuristic warning(s)."
            else:
                explanation = f"Classified as SPAM by ML language model with {spam_percentage}% spam probability."
        else:
            explanation = f"Classified as legitimate communication (HAM). Natural conversational or business vocabulary observed."

        return {
            "label": label,
            "is_spam": is_spam,
            "spam_probability": spam_percentage,
            "ham_probability": ham_percentage,
            "confidence": confidence,
            "risk_level": risk_level,
            "risk_score": int(spam_percentage),
            "trigger_words": triggers,
            "heuristics": heuristics,
            "explanation": explanation
        }

    def _tokenize_words(self, text: str) -> List[str]:
        """Extract clean word tokens, removing common English stop words."""
        STOP_WORDS = {
            "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
            "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
            "below", "between", "both", "but", "by", "can't", "cannot", "could", "did",
            "do", "does", "doing", "don't", "down", "during", "each", "few", "for", "from",
            "further", "had", "has", "have", "having", "he", "her", "here", "hers", "herself",
            "him", "himself", "his", "how", "i", "if", "in", "into", "is", "it", "its",
            "itself", "me", "more", "most", "my", "myself", "no", "nor", "not", "of", "off",
            "on", "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out",
            "over", "own", "same", "she", "should", "so", "some", "such", "than", "that",
            "the", "their", "theirs", "them", "themselves", "then", "there", "these", "they",
            "this", "those", "through", "to", "too", "under", "until", "up", "very", "was",
            "we", "were", "what", "when", "where", "which", "while", "who", "whom", "why",
            "with", "won't", "would", "you", "your", "yours", "yourself", "yourselves"
        }
        words = re.findall(r'\b[a-zA-Z]{2,}\b', text.lower())
        return [w for w in words if w not in STOP_WORDS]

    def calculate_similarity(self, email1: str, email2: str) -> Dict[str, Any]:
        """
        Calculates similarity between two emails to detect if they are the 'same' or duplicates.
        Uses:
        - TF-IDF Cosine Similarity
        - Jaccard Token Overlap
        - Levenshtein Sequence Matching Ratio
        """
        e1_clean = email1.strip()
        e2_clean = email2.strip()

        if not e1_clean and not e2_clean:
            return {
                "similarity_percentage": 100.0,
                "is_same": True,
                "match_type": "Identical",
                "summary": "Both emails are empty.",
                "matching_tokens": [],
                "metrics": {"cosine": 1.0, "jaccard": 1.0, "sequence": 1.0}
            }

        if not e1_clean or not e2_clean:
            return {
                "similarity_percentage": 0.0,
                "is_same": False,
                "match_type": "Different",
                "summary": "One email is empty while the other contains content.",
                "matching_tokens": [],
                "metrics": {"cosine": 0.0, "jaccard": 0.0, "sequence": 0.0}
            }

        # 1. Exact string match check
        if e1_clean.lower() == e2_clean.lower():
            tokens = self._tokenize_words(e1_clean)
            return {
                "similarity_percentage": 100.0,
                "is_same": True,
                "match_type": "Identical (100% Exact Match)",
                "summary": "These emails are character-for-character identical.",
                "matching_tokens": sorted(list(set(tokens)))[:15],
                "metrics": {"cosine": 1.0, "jaccard": 1.0, "sequence": 1.0}
            }

        # 2. Token extraction & Jaccard index
        tokens1 = set(self._tokenize_words(e1_clean))
        tokens2 = set(self._tokenize_words(e2_clean))
        
        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)
        jaccard_score = len(intersection) / len(union) if union else 0.0

        # 3. Sequence Matcher (Levenshtein-style character alignment)
        seq_ratio = difflib.SequenceMatcher(None, e1_clean.lower(), e2_clean.lower()).ratio()

        # 4. TF-IDF Cosine similarity
        if HAS_SKLEARN:
            try:
                tfidf_vec = TfidfVectorizer(stop_words='english', min_df=1)
                tfidf_matrix = tfidf_vec.fit_transform([e1_clean, e2_clean])
                cosine_sim = float(cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0])
            except Exception:
                cosine_sim = jaccard_score
        else:
            cosine_sim = jaccard_score

        # Composite score calculation
        # Cosine gives semantic vector alignment, Jaccard gives word coverage, Sequence checks phrasing
        composite = (cosine_sim * 0.45) + (jaccard_score * 0.35) + (seq_ratio * 0.20)
        similarity_percentage = round(min(max(composite * 100, 0.0), 100.0), 2)

        # Determine threshold & match classification
        is_same = similarity_percentage >= 80.0

        if similarity_percentage >= 95.0:
            match_type = "Near-Identical Clone"
            summary = "The emails are essentially identical with only trivial differences (e.g. minor typos or punctuation)."
        elif similarity_percentage >= 80.0:
            match_type = "Duplicate / Highly Similar"
            summary = "The emails share almost all key wording and structure. Highly likely a duplicate or copied email."
        elif similarity_percentage >= 50.0:
            match_type = "Partially Similar"
            summary = "The emails discuss related topics or share boilerplate phrasing, but contain notable differences."
        else:
            match_type = "Different Emails"
            summary = "The emails are distinct communications with low text overlap."

        return {
            "similarity_percentage": similarity_percentage,
            "is_same": is_same,
            "match_type": match_type,
            "summary": summary,
            "matching_tokens": sorted(list(intersection))[:20],
            "unique_to_email1": sorted(list(tokens1 - tokens2))[:10],
            "unique_to_email2": sorted(list(tokens2 - tokens1))[:10],
            "metrics": {
                "cosine_similarity": round(cosine_sim, 4),
                "jaccard_similarity": round(jaccard_score, 4),
                "character_ratio": round(seq_ratio, 4)
            }
        }

    def check_duplicate_in_library(self, email_text: str, library: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Compares an incoming email against a list of stored emails to find if it is already present.
        library format: [{'id': 1, 'subject': '...', 'body': '...'}]
        """
        best_match = None
        highest_score = -1.0

        results = []
        for item in library:
            target_text = f"{item.get('subject', '')} {item.get('body', '')}".strip()
            sim = self.calculate_similarity(email_text, target_text)
            score = sim["similarity_percentage"]
            
            res_entry = {
                "id": item.get("id"),
                "subject": item.get("subject", "No subject"),
                "similarity_percentage": score,
                "is_same": sim["is_same"],
                "match_type": sim["match_type"]
            }
            results.append(res_entry)

            if score > highest_score:
                highest_score = score
                best_match = res_entry

        # Sort descending by similarity
        results.sort(key=lambda x: x["similarity_percentage"], reverse=True)

        is_duplicate = highest_score >= 80.0
        return {
            "is_duplicate": is_duplicate,
            "highest_similarity": highest_score if highest_score >= 0 else 0.0,
            "best_match": best_match,
            "comparisons": results
        }
