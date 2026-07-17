"""
ThreatShield AI - Continuous Learning Service
Retrains the ML model using analyst feedback (false positives / corrections).
"""
import json
import logging
import pickle
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent.parent.parent / "ml_models" / "threat_classifier"
DATASET_PATH = Path(__file__).parent.parent.parent / "ml_models" / "training_data.json"
FEEDBACK_DATASET_PATH = Path(__file__).parent.parent.parent / "ml_models" / "feedback_data.json"

LABELS = ["safe", "bomb_threat", "violence", "terror", "extortion", "harassment", "school_threat"]
LABEL2ID = {l: i for i, l in enumerate(LABELS)}

# Track retrain status
_retrain_status = {
    "is_running": False,
    "last_run": None,
    "last_result": None,
    "feedback_count_at_last_train": 0,
}


def get_retrain_status() -> Dict:
    return dict(_retrain_status)


def save_feedback_to_dataset(email_text: str, correct_label: str):
    """Append a single feedback sample to the feedback dataset file."""
    sample = {"text": email_text, "label": correct_label, "source": "analyst_feedback"}

    existing = []
    if FEEDBACK_DATASET_PATH.exists():
        try:
            with open(FEEDBACK_DATASET_PATH) as f:
                existing = json.load(f)
        except Exception:
            existing = []

    existing.append(sample)

    FEEDBACK_DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(FEEDBACK_DATASET_PATH, "w") as f:
        json.dump(existing, f, indent=2)

    logger.info(f"Saved feedback sample. Total feedback samples: {len(existing)}")
    return len(existing)


def get_feedback_count() -> int:
    """Return number of feedback samples collected since last retrain."""
    if not FEEDBACK_DATASET_PATH.exists():
        return 0
    try:
        with open(FEEDBACK_DATASET_PATH) as f:
            data = json.load(f)
        return len(data)
    except Exception:
        return 0


def retrain_model(min_feedback_samples: int = 5) -> Dict:
    """
    Retrain the ML model combining original training data + analyst feedback.
    Returns a result dict with accuracy, sample counts, etc.
    """
    global _retrain_status

    if _retrain_status["is_running"]:
        return {"success": False, "message": "Retrain already in progress"}

    feedback_count = get_feedback_count()
    if feedback_count < min_feedback_samples:
        return {
            "success": False,
            "message": f"Need at least {min_feedback_samples} feedback samples. Currently have {feedback_count}.",
            "feedback_count": feedback_count,
        }

    _retrain_status["is_running"] = True

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
        import numpy as np

        # Load original training data
        original_data = []
        if DATASET_PATH.exists():
            with open(DATASET_PATH) as f:
                original_data = json.load(f)

        # Load feedback data
        feedback_data = []
        if FEEDBACK_DATASET_PATH.exists():
            with open(FEEDBACK_DATASET_PATH) as f:
                feedback_data = json.load(f)

        # Combine — feedback samples are weighted 3x to emphasize corrections
        combined_data = original_data + (feedback_data * 3)

        logger.info(
            f"Retraining with {len(original_data)} original + "
            f"{len(feedback_data)} feedback samples ({len(combined_data)} total)"
        )

        # Filter valid labels only
        combined_data = [d for d in combined_data if d["label"] in LABEL2ID]

        texts = [d["text"] for d in combined_data]
        labels = [LABEL2ID[d["label"]] for d in combined_data]

        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 3),
                max_features=15000,
                sublinear_tf=True,
                min_df=1,
                token_pattern=r"(?u)\b\w+\b",
            )),
            ("clf", LogisticRegression(
                max_iter=2000,
                C=2.0,
                class_weight="balanced",
                solver="lbfgs",
                random_state=42,
            )),
        ])

        pipeline.fit(X_train, y_train)

        y_pred = pipeline.predict(X_test)
        acc = float(np.mean(np.array(y_pred) == np.array(y_test)))

        # Save new model
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        with open(MODEL_DIR / "sklearn_model.pkl", "wb") as f:
            pickle.dump(pipeline, f)

        meta = {
            "model_type": "tfidf_logreg_retrained",
            "labels": LABELS,
            "label2id": LABEL2ID,
            "id2label": {str(i): l for i, l in enumerate(LABELS)},
            "training_samples": len(combined_data),
            "original_samples": len(original_data),
            "feedback_samples": len(feedback_data),
            "test_accuracy": acc,
            "retrained_at": datetime.utcnow().isoformat(),
        }
        with open(MODEL_DIR / "metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

        # Clear feedback file after successful retrain
        with open(FEEDBACK_DATASET_PATH, "w") as f:
            json.dump([], f)

        # Reload the classifier singleton
        from app.services.ml_classifier import ml_classifier
        ml_classifier._load_model()

        result = {
            "success": True,
            "accuracy": round(acc, 4),
            "total_samples": len(combined_data),
            "original_samples": len(original_data),
            "feedback_samples": len(feedback_data),
            "message": f"Model retrained successfully. Accuracy: {acc:.2%}",
        }

        _retrain_status["last_run"] = datetime.utcnow().isoformat()
        _retrain_status["last_result"] = result
        _retrain_status["feedback_count_at_last_train"] = len(feedback_data)

        logger.info(f"Retrain complete. Accuracy: {acc:.2%}")
        return result

    except Exception as e:
        logger.error(f"Retrain failed: {e}")
        result = {"success": False, "message": str(e)}
        _retrain_status["last_result"] = result
        return result

    finally:
        _retrain_status["is_running"] = False


async def retrain_model_async(min_feedback_samples: int = 5) -> Dict:
    """Run retrain in a thread so it doesn't block the API."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, retrain_model, min_feedback_samples)