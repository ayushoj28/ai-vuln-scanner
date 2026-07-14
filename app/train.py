"""
train.py — Trains a Random Forest classifier on SERVER RESPONSE text.

Pipeline:
  Response text dataset
        ↓
  TF-IDF Vectorizer (word n-grams 1-3)
        ↓
  train_test_split (80% train / 20% test, random_state=42)
        ↓
  RandomForestClassifier.fit(X_train, y_train)
        ↓
  accuracy_score(y_test, prediction)
        ↓
  joblib.dump(model, "model.pkl")
        joblib.dump(vectorizer, "vectorizer.pkl")
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

try:
    from app.dataset import generate_dataset
except ImportError:
    from dataset import generate_dataset

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "metrics.pkl")

CLASS_NAMES = {
    0: "Normal",
    1: "SQL Injection",
    2: "XSS",
    3: "Prompt Injection",
    4: "Data Leakage"
}


def train_model(dataset_size=1200):
    print(f"[TRAIN] Generating response-based dataset ({dataset_size} samples)...")
    raw = generate_dataset(dataset_size)
    df = pd.DataFrame(raw)

    X = df["response"]
    y = df["label"]

    print("[TRAIN] Applying TF-IDF vectorization (word n-grams 1-3)...")
    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 3),
        max_features=8000,
        lowercase=True,
        min_df=1
    )
    X_vec = vectorizer.fit_transform(X)

    # 80/20 train-test split
    print("[TRAIN] Splitting dataset: 80% train / 20% test (random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_vec, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"[TRAIN] Training samples: {X_train.shape[0]} | Test samples: {X_test.shape[0]}")

    # Train Random Forest
    print("[TRAIN] Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Evaluate
    prediction = model.predict(X_test)
    acc = accuracy_score(y_test, prediction)
    report = classification_report(y_test, prediction, target_names=list(CLASS_NAMES.values()), output_dict=True)

    print(f"[TRAIN] Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, prediction, target_names=list(CLASS_NAMES.values())))

    # Save model, vectorizer, metrics
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump({
        "accuracy": acc,
        "report": report,
        "dataset_size": dataset_size,
        "class_names": CLASS_NAMES
    }, METRICS_PATH)

    print(f"[TRAIN] Saved model → {MODEL_PATH}")
    print(f"[TRAIN] Saved vectorizer → {VECTORIZER_PATH}")
    return acc


if __name__ == "__main__":
    train_model()
