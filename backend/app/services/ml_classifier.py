"""
LOCATION: threatshield-ai/backend/app/services/ml_classifier.py

ThreatShield AI - ML Classifier Service

Loads and runs the full 3-model soft-voting ensemble:
  1. TF-IDF + LogisticRegression   (well-calibrated probabilities)
  2. TF-IDF + XGBoost              (non-linear feature interactions)
  3. TF-IDF + RandomForest         (variance reduction / robustness)

Load order:
  1. ensemble_model.pkl  — full 3-model ensemble (preferred)
  2. sklearn_model.pkl   — LogReg only (backward-compat fallback)
  3. Neither found       — rule-based detection only (graceful degradation)

Train with:
  cd backend
  pip install xgboost scikit-learn
  python ml_models/train.py
"""
import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

MODEL_DIR     = Path(__file__).parent.parent.parent / "ml_models" / "threat_classifier"
ENSEMBLE_PATH = MODEL_DIR / "ensemble_model.pkl"
COMPAT_PATH   = MODEL_DIR / "sklearn_model.pkl"
META_PATH     = MODEL_DIR / "metadata.json"

LABELS = ["safe", "bomb_threat", "violence", "terror", "extortion", "harassment", "school_threat"]

REQUIRED_ENSEMBLE_MEMBERS = {"logreg", "xgboost", "random_forest"}


class MLClassifierResult:
    def __init__(
        self,
        predicted_label: str,
        confidence: float,
        all_scores: Dict[str, float],
        model_available: bool = True,
        model_type: str = "unknown",
        ensemble_members: Optional[List[str]] = None,
    ):
        self.predicted_label = predicted_label
        self.confidence = confidence
        self.all_scores = all_scores
        self.model_available = model_available
        self.model_type = model_type
        self.ensemble_members = ensemble_members or []


class MLClassifier:
    """
    Loads and runs the trained 3-model threat classification ensemble.

    Ensemble prediction uses soft voting:
      final_proba = mean(logreg_proba, xgboost_proba, rf_proba)

    This consistently outperforms any single model because:
      - LogReg gives well-calibrated probabilities
      - XGBoost captures non-linear feature interactions
      - RandomForest reduces variance / overfitting
    """

    def __init__(self):
        self._ensemble: Optional[list] = None
        self._ensemble_member_names: List[str] = []
        self._compat_model = None
        self._metadata: Optional[dict] = None
        self._loaded = False
        self._model_type = "unknown"
        self._load_model()

    def _load_model(self):
        """Load ensemble (preferred) or compat single model. Called once at startup."""

        # ── Try full ensemble first ───────────────────────────────────────────
        if ENSEMBLE_PATH.exists():
            try:
                with open(ENSEMBLE_PATH, "rb") as f:
                    bundle = pickle.load(f)

                models = bundle.get("models", [])
                names  = bundle.get("model_names", [])

                if not models:
                    raise ValueError("Ensemble bundle contains no models")

                # Validate all 3 required members are present
                present = set(names)
                missing = REQUIRED_ENSEMBLE_MEMBERS - present
                if missing:
                    logger.warning(
                        f"Ensemble is missing members: {missing}. "
                        f"Re-run ml_models/train.py with xgboost installed "
                        f"(pip install xgboost) to get the full 3-model ensemble."
                    )
                else:
                    logger.info("Full 3-model ensemble loaded: LogReg + XGBoost + RandomForest")

                self._ensemble = models
                self._ensemble_member_names = names
                self._model_type = "ensemble_v2" if len(models) == 3 else "ensemble_partial"
                self._loaded = True
                logger.info(f"Ensemble ML classifier loaded — members: {names}")

            except Exception as e:
                logger.error(f"Failed to load ensemble model: {e}")

        # ── Fall back to single LogReg model ──────────────────────────────────
        if not self._loaded and COMPAT_PATH.exists():
            try:
                with open(COMPAT_PATH, "rb") as f:
                    self._compat_model = pickle.load(f)
                self._model_type = "logreg"
                self._loaded = True
                logger.warning(
                    "Loaded backward-compat LogReg model only. "
                    "Re-run ml_models/train.py to build the full ensemble."
                )
            except Exception as e:
                logger.error(f"Failed to load compat ML model: {e}")

        if not self._loaded:
            logger.warning(
                "No ML model found. Run:\n"
                "  pip install xgboost scikit-learn\n"
                "  python ml_models/train.py\n"
                "Falling back to rule-based detection only."
            )
            return

        # ── Load metadata ─────────────────────────────────────────────────────
        if META_PATH.exists():
            try:
                with open(META_PATH) as f:
                    self._metadata = json.load(f)
                acc     = self._metadata.get("test_accuracy", 0)
                samples = self._metadata.get("training_samples", 0)
                members = self._metadata.get("ensemble_members", [self._model_type])
                xgb_acc = self._metadata.get("xgboost_accuracy")
                rf_acc  = self._metadata.get("random_forest_accuracy")
                lr_acc  = self._metadata.get("logreg_accuracy")
                logger.info(
                    f"ML metadata: ensemble_acc={acc:.2%}, samples={samples}, "
                    f"members={members} | logreg={lr_acc:.2%} xgb={xgb_acc:.2%} rf={rf_acc:.2%}"
                    if xgb_acc and rf_acc and lr_acc else
                    f"ML metadata: accuracy={acc:.2%}, samples={samples}, members={members}"
                )
            except Exception as e:
                logger.warning(f"Could not load ML metadata: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        return self._loaded and (
            self._ensemble is not None or self._compat_model is not None
        )

    @property
    def is_full_ensemble(self) -> bool:
        """True only when all 3 models (LogReg + XGBoost + RandomForest) are loaded."""
        return (
            self._ensemble is not None
            and REQUIRED_ENSEMBLE_MEMBERS.issubset(set(self._ensemble_member_names))
        )

    def classify(self, text: str) -> MLClassifierResult:
        """
        Classify email text using the loaded model(s).

        Returns MLClassifierResult with:
          - predicted_label: most likely threat category
          - confidence: probability of the predicted label
          - all_scores: per-class probability dict
          - model_type: which model path was used
          - ensemble_members: list of active ensemble member names
        """
        if not self.is_available:
            return MLClassifierResult(
                predicted_label="unknown",
                confidence=0.0,
                all_scores={},
                model_available=False,
                model_type="unknown",
            )

        try:
            if self._ensemble is not None:
                proba = self._ensemble_predict_proba(text)
            else:
                proba = self._compat_model.predict_proba([text])[0]

            label_id        = int(np.argmax(proba))
            predicted_label = LABELS[label_id]
            confidence      = float(proba[label_id])

            all_scores = {
                label: round(float(p), 4)
                for label, p in zip(LABELS, proba)
            }

            return MLClassifierResult(
                predicted_label=predicted_label,
                confidence=round(confidence, 4),
                all_scores=all_scores,
                model_available=True,
                model_type=self._model_type,
                ensemble_members=list(self._ensemble_member_names),
            )

        except Exception as e:
            logger.error(f"ML classification error: {e}")
            return MLClassifierResult(
                predicted_label="unknown",
                confidence=0.0,
                all_scores={},
                model_available=False,
                model_type="unknown",
            )

    def get_threat_probability(self, text: str) -> float:
        """
        Returns probability that the email contains ANY threat.
        (1 - probability of being safe)
        """
        result = self.classify(text)
        if not result.model_available:
            return 0.0
        safe_prob = result.all_scores.get("safe", 1.0)
        return round(1.0 - safe_prob, 4)

    def get_metadata(self) -> dict:
        """Return training metadata dict, or empty dict if not loaded."""
        return self._metadata or {}

    def get_model_status(self) -> dict:
        """Return a status dict for health-check / admin endpoints."""
        return {
            "loaded": self._loaded,
            "model_type": self._model_type,
            "is_full_ensemble": self.is_full_ensemble,
            "ensemble_members": list(self._ensemble_member_names),
            "missing_members": list(
                REQUIRED_ENSEMBLE_MEMBERS - set(self._ensemble_member_names)
            ),
            "metadata": self._metadata or {},
        }

    # ── Ensemble inference ────────────────────────────────────────────────────

    def _ensemble_predict_proba(self, text: str) -> np.ndarray:
        """
        Run all ensemble members on `text` and return soft-voted probabilities.

        Each member is one of:
          - sklearn Pipeline (LogReg): .predict_proba([text])
          - dict {"vec": TfidfVectorizer, "clf": XGBClassifier/RF, "type": str}
        """
        probas = []
        for member in self._ensemble:
            try:
                if isinstance(member, dict):
                    vec = member["vec"]
                    clf = member["clf"]
                    X   = vec.transform([text])
                    p   = clf.predict_proba(X)[0]
                else:
                    # sklearn Pipeline (LogReg)
                    p = member.predict_proba([text])[0]

                if len(p) == len(LABELS):
                    probas.append(p)
                else:
                    logger.warning(
                        f"Ensemble member returned {len(p)} classes, expected {len(LABELS)}. Skipping."
                    )
            except Exception as e:
                logger.warning(f"Ensemble member predict failed: {e}")

        if not probas:
            raise RuntimeError("All ensemble members failed to predict")

        # Soft vote — simple average of probabilities
        avg = np.mean(probas, axis=0)

        # Normalise in case of floating-point drift
        total = avg.sum()
        if total > 0:
            avg = avg / total

        return avg


# Singleton — loaded once when the backend starts
ml_classifier = MLClassifier()