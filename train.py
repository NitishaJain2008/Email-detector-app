"""
Training script for Email Spam Detector model.
Trains a TF-IDF + Multinomial Naive Bayes pipeline on data/sample_emails.csv
and saves the trained model to data/model.pkl.
"""

import os
import sys
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from model import EmailDetector, HAS_SKLEARN


def train():
    if not HAS_SKLEARN:
        print("Error: scikit-learn is required to train the model.")
        sys.exit(1)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "data", "sample_emails.csv")
    model_path = os.path.join(base_dir, "data", "model.pkl")

    print("==================================================")
    print("   Email Spam & Duplicate Detector Model Trainer  ")
    print("==================================================")
    print(f"Loading dataset from: {dataset_path}")

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)

    df = pd.read_csv(dataset_path)
    print(f"Total samples loaded: {len(df)}")
    print(f" - Spam samples (label=1): {(df['label'] == 1).sum()}")
    print(f" - Ham/Legitimate samples (label=0): {(df['label'] == 0).sum()}")

    # Initialize detector and train
    detector = EmailDetector(model_path=model_path, dataset_path=dataset_path)
    success = detector.train_from_csv(dataset_path)

    if not success:
        print("Training failed.")
        sys.exit(1)

    print(f"\nModel successfully trained and saved to: {model_path}")

    # Evaluate on test split for reporting
    texts = (df['subject'].fillna('') + " " + df['body'].fillna('')).apply(detector.preprocess_text)
    labels = df['label'].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )

    detector.pipeline.fit(X_train, y_train)
    y_pred = detector.pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"\n--- Validation Performance (Holdout Set) ---")
    print(f"Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["HAM (Legit)", "SPAM"]))

    # Refit on full dataset for final export
    detector.pipeline.fit(texts, labels)
    import joblib
    joblib.dump(detector.pipeline, model_path)
    print("Final model refitted on full dataset and persisted.")

    # Demonstration of Spam prediction
    print("\n--- Testing Demonstration ---")
    sample_spam = "URGENT: Your PayPal account is frozen. Click here to verify credentials and claim $500 reward."
    res_spam = detector.predict_spam(sample_spam)
    print(f"Test 1 (Spam text):")
    print(f" -> Verdict: {res_spam['label']} | Probability: {res_spam['spam_probability']}% | Risk: {res_spam['risk_level']}")

    sample_ham = "Hi team, let's meet on Zoom tomorrow at 3 PM to review the quarterly budget spreadsheet."
    res_ham = detector.predict_spam(sample_ham)
    print(f"Test 2 (Ham text):")
    print(f" -> Verdict: {res_ham['label']} | Probability: {res_ham['spam_probability']}% | Risk: {res_ham['risk_level']}")

    # Demonstration of Duplicate/Similarity detection
    print("\n--- Testing Email Duplicate / Similarity Detection ---")
    e1 = "Hi team, please find attached the meeting minutes and project update for Q3."
    e2 = "Hi team, please find attached the updated meeting minutes and project summary for Q3."
    sim_res = detector.calculate_similarity(e1, e2)
    print(f"Email 1: {e1}")
    print(f"Email 2: {e2}")
    print(f" -> Similarity: {sim_res['similarity_percentage']}% | Match Type: {sim_res['match_type']} | Is Same: {sim_res['is_same']}")
    print("==================================================")


if __name__ == "__main__":
    train()
