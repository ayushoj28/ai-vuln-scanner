"""
model.py — Loads the trained model and classifies server response text.
"""

import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "metrics.pkl")

CLASS_NAMES = {
    0: "Normal",
    1: "SQL Injection",
    2: "Cross-Site Scripting (XSS)",
    3: "Prompt Injection",
    4: "Data Leakage"
}

SEVERITY = {
    0: "INFO",
    1: "HIGH",
    2: "HIGH",
    3: "MEDIUM",
    4: "CRITICAL"
}


class VulnerabilityModel:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metrics = None
        self._load()

    def _load(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.vectorizer = joblib.load(VECTORIZER_PATH)
                if os.path.exists(METRICS_PATH):
                    self.metrics = joblib.load(METRICS_PATH)
                print("[MODEL] Artifacts loaded successfully.")
            except Exception as e:
                print(f"[MODEL] Load error: {e}")
                self.model = None
                self.vectorizer = None
        else:
            print("[MODEL] Artifacts not found. Run training first.")

    def is_loaded(self):
        return self.model is not None and self.vectorizer is not None

    def predict(self, response_text: str) -> dict:
        """
        Classify a server response string.
        Returns dict with label, class name, severity, confidence, probabilities.
        """
        if not self.is_loaded():
            return {"error": "Model not loaded. Please train first."}

        vec = self.vectorizer.transform([response_text])
        label = int(self.model.predict(vec)[0])
        proba = self.model.predict_proba(vec)[0].tolist()

        return {
            "label": label,
            "class_name": CLASS_NAMES.get(label, "Unknown"),
            "severity": SEVERITY.get(label, "INFO"),
            "confidence": round(proba[label] * 100, 1),
            "probabilities": {
                CLASS_NAMES[i]: round(p * 100, 1)
                for i, p in enumerate(proba)
                if i in CLASS_NAMES
            }
        }
