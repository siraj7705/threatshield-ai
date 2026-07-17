# LOCATION: backend/ml_models/train.py
# ================================================================
# ThreatShield AI — Full 3-Model Ensemble Trainer
#
# Trains ALL THREE models and saves them as an ensemble:
#   1. TF-IDF + LogisticRegression   (fast, well-calibrated baseline)
#   2. TF-IDF + XGBoost              (gradient-boosted trees, strong recall)
#   3. TF-IDF + RandomForest         (robust, handles noisy data well)
#
# Predictions are combined via soft-voting (average of probabilities).
# The ensemble consistently outperforms any single model on short-text
# multi-class threat classification.
#
# Prerequisites:
#   pip install scikit-learn xgboost numpy
#
# Run AFTER generate_dataset.py:
#   cd backend
#   python ml_models/generate_dataset.py   # build/update dataset
#   python ml_models/train.py              # train & save ensemble
#
# XGBoost is NOW REQUIRED. The script will exit with a clear error
# if it is not installed, rather than silently building an incomplete
# 2-model ensemble.
# ================================================================

import json
import pickle
import sys
import numpy as np
from pathlib import Path
from collections import Counter

# ── Dependency check — fail fast with a clear message ────────────────────────
def _check_dependencies():
    missing = []
    try:
        import sklearn  # noqa: F401
    except ImportError:
        missing.append("scikit-learn")

    try:
        import xgboost  # noqa: F401
    except ImportError:
        missing.append("xgboost")

    if missing:
        print(
            f"\n❌  Missing required packages: {', '.join(missing)}\n"
            f"    Install with:\n"
            f"      pip install {' '.join(missing)}\n"
            f"    Then re-run this script.\n"
        )
        sys.exit(1)

_check_dependencies()

# ── Paths ─────────────────────────────────────────────────────────────────────
MODEL_DIR  = Path(__file__).parent                           # backend/ml_models/
REPO_ROOT  = MODEL_DIR.parent.parent                         # threatshield-ai/
OUTPUT_DIR = MODEL_DIR / "threat_classifier"

_DATASET_CANDIDATES = [
    REPO_ROOT / "training_data.json",        # repo root (default)
    MODEL_DIR.parent / "training_data.json", # backend/training_data.json
    MODEL_DIR / "training_data.json",        # backend/ml_models/training_data.json
]
DATASET_PATH = next((p for p in _DATASET_CANDIDATES if p.exists()), _DATASET_CANDIDATES[0])

LABELS   = ["safe", "bomb_threat", "violence", "terror", "extortion", "harassment", "school_threat"]
LABEL2ID = {l: i for i, l in enumerate(LABELS)}
ID2LABEL = {i: l for i, l in enumerate(LABELS)}


# ── Data loading ──────────────────────────────────────────────────────────────

def load_data():
    if not DATASET_PATH.exists():
        checked = "\n  ".join(str(p) for p in _DATASET_CANDIDATES)
        raise FileNotFoundError(
            f"Dataset not found. Looked in:\n  {checked}\n"
            "Run: python ml_models/generate_dataset.py  OR  copy "
            "training_data.json to the repo root."
        )
    with open(DATASET_PATH) as f:
        data = json.load(f)

    counts = Counter(d["label"] for d in data)
    print(f"Loaded {len(data)} samples:")
    for label in LABELS:
        print(f"  {label}: {counts.get(label, 0)}")
    return data


# ── Shared TF-IDF vectoriser ──────────────────────────────────────────────────

def build_vectorizer():
    from sklearn.feature_extraction.text import TfidfVectorizer
    return TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=20_000,
        sublinear_tf=True,
        analyzer="word",
        min_df=1,
        token_pattern=r"(?u)\b\w+\b",
    )


# ── Individual model builders ─────────────────────────────────────────────────

def build_logreg():
    from sklearn.linear_model import LogisticRegression
    return LogisticRegression(
        max_iter=2000,
        C=2.0,
        class_weight="balanced",
        solver="lbfgs",
        random_state=42,
    )


def build_xgboost(n_classes: int):
    from xgboost import XGBClassifier
    return XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        objective="multi:softprob",
        num_class=n_classes,
        random_state=42,
        verbosity=0,
        n_jobs=-1,
    )


def build_random_forest():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )


# ── Ensemble trainer ──────────────────────────────────────────────────────────

def train_ensemble(data):
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.metrics import classification_report
    from sklearn.pipeline import Pipeline

    texts  = [d["text"] for d in data]
    labels = [LABEL2ID[d["label"]] for d in data]

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    n_classes      = len(LABELS)
    models_trained = []
    model_names    = []
    accuracies     = {}

    # ── 1. LogisticRegression ─────────────────────────────────────────────────
    print("\n[1/3] Training TF-IDF + LogisticRegression ...")
    lr_pipeline = Pipeline([
        ("tfidf", build_vectorizer()),
        ("clf",   build_logreg()),
    ])
    lr_pipeline.fit(X_train, y_train)
    lr_acc = float(np.mean(np.array(lr_pipeline.predict(X_test)) == np.array(y_test)))
    print(f"      Test accuracy: {lr_acc:.2%}")
    models_trained.append(lr_pipeline)
    model_names.append("logreg")
    accuracies["logreg_accuracy"] = lr_acc

    # ── 2. XGBoost ────────────────────────────────────────────────────────────
    print("\n[2/3] Training TF-IDF + XGBoost ...")
    xgb_vec = build_vectorizer()
    X_tr_xgb = xgb_vec.fit_transform(X_train)
    X_te_xgb = xgb_vec.transform(X_test)
    xgb_clf = build_xgboost(n_classes)
    xgb_clf.fit(X_tr_xgb, y_train)
    xgb_preds = xgb_clf.predict(X_te_xgb)
    xgb_acc = float(np.mean(np.array(xgb_preds) == np.array(y_test)))
    print(f"      Test accuracy: {xgb_acc:.2%}")
    models_trained.append({"vec": xgb_vec, "clf": xgb_clf, "type": "xgboost"})
    model_names.append("xgboost")
    accuracies["xgboost_accuracy"] = xgb_acc

    # ── 3. RandomForest ───────────────────────────────────────────────────────
    print("\n[3/3] Training TF-IDF + RandomForest ...")
    rf_vec = build_vectorizer()
    X_tr_rf = rf_vec.fit_transform(X_train)
    X_te_rf = rf_vec.transform(X_test)
    rf_clf = build_random_forest()
    rf_clf.fit(X_tr_rf, y_train)
    rf_preds = rf_clf.predict(X_te_rf)
    rf_acc = float(np.mean(np.array(rf_preds) == np.array(y_test)))
    print(f"      Test accuracy: {rf_acc:.2%}")
    models_trained.append({"vec": rf_vec, "clf": rf_clf, "type": "random_forest"})
    model_names.append("random_forest")
    accuracies["random_forest_accuracy"] = rf_acc

    # ── Ensemble evaluation ───────────────────────────────────────────────────
    print("\n[Ensemble] Evaluating soft-vote ensemble on test set ...")
    ensemble_proba = _ensemble_predict_proba_batch(models_trained, X_test)
    ensemble_preds = np.argmax(ensemble_proba, axis=1)
    ensemble_acc   = float(np.mean(ensemble_preds == np.array(y_test)))
    print(f"      Ensemble test accuracy: {ensemble_acc:.2%}")
    print("\nClassification Report (Ensemble):")
    print(classification_report(y_test, ensemble_preds, target_names=LABELS))

    # 5-fold CV on LogReg (fast proxy for ensemble stability)
    print("\n[CV] 5-fold cross-validation on LogReg pipeline ...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(lr_pipeline, texts, labels, cv=cv, scoring="accuracy")
    print(f"     5-Fold CV: {cv_scores.mean():.2%} ± {cv_scores.std():.2%}")

    # ── Save ensemble ─────────────────────────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    ensemble_path = OUTPUT_DIR / "ensemble_model.pkl"
    with open(ensemble_path, "wb") as f:
        pickle.dump({"models": models_trained, "model_names": model_names}, f)
    print(f"\n✅ Ensemble saved → {ensemble_path}")

    # Backward-compat single model
    compat_path = OUTPUT_DIR / "sklearn_model.pkl"
    with open(compat_path, "wb") as f:
        pickle.dump(lr_pipeline, f)
    print(f"✅ LogReg (compat) saved → {compat_path}")

    # Metadata
    meta = {
        "model_type": "ensemble_v2",
        "ensemble_members": model_names,
        "labels": LABELS,
        "label2id": LABEL2ID,
        "id2label": ID2LABEL,
        "training_samples": len(data),
        "test_accuracy": ensemble_acc,
        "cv_accuracy_mean": float(cv_scores.mean()),
        "cv_accuracy_std": float(cv_scores.std()),
        **accuracies,
    }
    meta_path = OUTPUT_DIR / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"✅ Metadata saved → {meta_path}")

    return models_trained


# ── Batch inference helper (used during training evaluation only) ─────────────

def _ensemble_predict_proba_batch(models, X_test_texts_or_matrix):
    """
    Average predicted probabilities from all models over a batch.
    X_test_texts_or_matrix can be a list of strings or a pre-vectorised matrix.
    """
    import scipy.sparse
    raw_text = (
        isinstance(X_test_texts_or_matrix, list)
        and X_test_texts_or_matrix
        and isinstance(X_test_texts_or_matrix[0], str)
    )
    probas = []
    for m in models:
        if isinstance(m, dict):
            vec = m["vec"]
            clf = m["clf"]
            X   = vec.transform(X_test_texts_or_matrix) if raw_text else X_test_texts_or_matrix
            probas.append(clf.predict_proba(X))
        else:
            probas.append(m.predict_proba(X_test_texts_or_matrix))
    if not probas:
        raise ValueError("No models produced probabilities")
    return np.mean(probas, axis=0)


# ── Smoke test ────────────────────────────────────────────────────────────────

SMOKE_TEST = [
    ("I'm going to destroy you at tennis on Saturday.",                          "safe"),
    ("Kill the Jenkins build and restart it.",                                   "safe"),
    ("Our CEO is on the warpath about the deadline.",                            "safe"),
    ("I'd evacuate that building if I were you. Something's ticking in there.",  "bomb_threat"),
    ("Don't go into work tomorrow. Trust me on this one.",                       "bomb_threat"),
    ("That unattended bag by gate 14 isn't lost luggage.",                       "bomb_threat"),
    ("Say your goodbyes while you still can.",                                   "violence"),
    ("You've got maybe two days left if you keep this up.",                      "violence"),
    ("You fired the wrong person. I'll make sure you regret that decision.",     "violence"),
    ("It would be a shame if certain people found out what you've been up to.",  "extortion"),
    ("I've been holding onto this material. I'd like to discuss terms.",         "extortion"),
    ("Nice haircut. I saw you at the salon on Thursday.",                        "harassment"),
    ("You should really draw your blinds at night.",                             "harassment"),
    ("I'd keep your kids home on Thursday if I were you.",                       "school_threat"),
    ("I've been going to the range every week. The kids at my school will find out why.", "school_threat"),
    ("The brothers are in position. The timeline has been moved up to Friday.",  "terror"),
    ("The operation goes live at the signal. Targets have been identified.",     "terror"),
]


def run_smoke_test(models_trained):
    print("\n" + "=" * 65)
    print("SMOKE TEST — oblique / colloquial phrasing (full ensemble)")
    print("=" * 65)
    correct = 0
    for text, expected in SMOKE_TEST:
        proba   = _ensemble_predict_proba_batch(models_trained, [text])[0]
        pred_id = int(np.argmax(proba))
        pred    = ID2LABEL[pred_id]
        conf    = proba[pred_id]
        ok      = "✓" if pred == expected else "✗"
        if pred == expected:
            correct += 1
        print(f"{ok} [{expected:15s} → {pred:15s}] ({conf:.0%})  {text[:58]}")
    total = len(SMOKE_TEST)
    pct   = correct / total
    print(f"\nSmoke test: {correct}/{total} correct ({pct:.0%})")
    if pct < 0.70:
        print("⚠️  Below 70% — consider adding more training data.")
    else:
        print("✅ Smoke test passed.")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 65)
    print("ThreatShield AI — Full Ensemble ML Trainer")
    print("Models: LogisticRegression + XGBoost + RandomForest")
    print("=" * 65)

    data   = load_data()
    models = train_ensemble(data)
    run_smoke_test(models)

    print("\n✅ Training complete!")
    print("Restart the backend to auto-load the new full ensemble model.")