# LOCATION: backend/ml_models/train.py
# ================================================================
# Train the ThreatShield ML classifier.
# Run AFTER generate_dataset.py:
#   cd backend
#   python ml_models/generate_dataset.py   # build/update dataset
#   python ml_models/train.py              # train & save model
# ================================================================

import json
import pickle
import numpy as np
from pathlib import Path
from collections import Counter

MODEL_DIR   = Path(__file__).parent
DATASET_PATH = MODEL_DIR / "training_data.json"
OUTPUT_DIR  = MODEL_DIR / "threat_classifier"

LABELS   = ["safe", "bomb_threat", "violence", "terror", "extortion", "harassment", "school_threat"]
LABEL2ID = {l: i for i, l in enumerate(LABELS)}
ID2LABEL = {i: l for i, l in enumerate(LABELS)}


def load_data():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}\n"
            "Run: python ml_models/generate_dataset.py"
        )
    with open(DATASET_PATH) as f:
        data = json.load(f)

    counts = Counter(d["label"] for d in data)
    print(f"Loaded {len(data)} samples:")
    for label in LABELS:
        print(f"  {label}: {counts.get(label, 0)}")
    return data


def train_sklearn_model(data):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import LinearSVC
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.metrics import classification_report
    from sklearn.calibration import CalibratedClassifierCV

    print("\nTraining TF-IDF + Logistic Regression classifier...")

    texts  = [d["text"] for d in data]
    labels = [LABEL2ID[d["label"]] for d in data]

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # Wider n-gram range + char n-grams to capture oblique phrasing
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=15000,
            sublinear_tf=True,
            analyzer="word",
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
    print(f"\nTest accuracy: {acc:.2%}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=LABELS))

    # 5-fold CV for a more reliable accuracy estimate
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, texts, labels, cv=cv, scoring="accuracy")
    print(f"5-Fold CV accuracy: {cv_scores.mean():.2%} ± {cv_scores.std():.2%}")

    # Save
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model_path = OUTPUT_DIR / "sklearn_model.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(pipeline, f)

    meta = {
        "model_type": "tfidf_logreg",
        "labels": LABELS,
        "label2id": LABEL2ID,
        "id2label": ID2LABEL,
        "training_samples": len(data),
        "test_accuracy": acc,
        "cv_accuracy_mean": float(cv_scores.mean()),
        "cv_accuracy_std": float(cv_scores.std()),
    }
    with open(OUTPUT_DIR / "metadata.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nModel saved → {model_path}")
    return pipeline


# ── Quick smoke test with oblique / colloquial phrases ───────────────────────
SMOKE_TEST = [
    # Should be SAFE
    ("I'm going to destroy you at tennis on Saturday.", "safe"),
    ("Kill the Jenkins build and restart it.", "safe"),
    ("Our CEO is on the warpath about the deadline.", "safe"),
    # Should be BOMB
    ("I'd evacuate that building if I were you. Something's ticking in there.", "bomb_threat"),
    ("Don't go into work tomorrow. Trust me on this one.", "bomb_threat"),
    ("That unattended bag by gate 14 isn't lost luggage.", "bomb_threat"),
    # Should be VIOLENCE
    ("Say your goodbyes while you still can.", "violence"),
    ("You've got maybe two days left if you keep this up.", "violence"),
    ("You fired the wrong person. I'll make sure you regret that decision.", "violence"),
    # Should be EXTORTION
    ("It would be a shame if certain people found out what you've been up to.", "extortion"),
    ("I've been holding onto this material. I'd like to discuss terms.", "extortion"),
    # Should be HARASSMENT
    ("Nice haircut. I saw you at the salon on Thursday.", "harassment"),
    ("You should really draw your blinds at night.", "harassment"),
    # Should be SCHOOL_THREAT
    ("I'd keep your kids home on Thursday if I were you.", "school_threat"),
    ("I've been going to the range every week. The kids at my school will find out why.", "school_threat"),
    # Should be TERROR
    ("The brothers are in position. The timeline has been moved up to Friday.", "terror"),
    ("The operation goes live at the signal. Targets have been identified.", "terror"),
]


def run_smoke_test(pipeline):
    print("\n" + "=" * 60)
    print("SMOKE TEST — oblique / colloquial phrasing")
    print("=" * 60)
    correct = 0
    for text, expected in SMOKE_TEST:
        pred_id = pipeline.predict([text])[0]
        pred = ID2LABEL[pred_id]
        ok = "✓" if pred == expected else "✗"
        if pred == expected:
            correct += 1
        print(f"{ok} [{expected:15s}→{pred:15s}] {text[:70]}")
    print(f"\nSmoke test: {correct}/{len(SMOKE_TEST)} correct "
          f"({correct/len(SMOKE_TEST):.0%})")


if __name__ == "__main__":
    print("=" * 60)
    print("ThreatShield AI — ML Model Trainer")
    print("=" * 60)

    data     = load_data()
    pipeline = train_sklearn_model(data)
    run_smoke_test(pipeline)

    print("\n✅ Training complete!")
    print("Restart the backend to auto-load the new model.")