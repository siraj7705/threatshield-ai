"""
LOCATION: threatshield-ai/backend/app/services/nlp_engine.py

ThreatShield AI - NLP Threat Detection Engine
Multi-layer threat detection:
  Layer 1: Keyword matching
  Layer 2: Phrase/regex pattern matching
  Layer 3: Urgency scoring
  Layer 4: Target extraction
  Layer 5: Entity extraction  ← NOW REAL spaCy NER (PERSON, ORG, GPE, LOC, FAC, DATE, TIME, MONEY, QUANTITY)
  Layer 6: ML classifier (TF-IDF + Logistic Regression)
"""
import re
import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# spaCy lazy-loader
# ---------------------------------------------------------------------------
_spacy_nlp = None
_spacy_available = False


def _get_spacy():
    """
    Lazy-load spaCy model once.  Falls back to None if spaCy or the model
    is not installed — the rest of the engine degrades gracefully to the
    regex fallback.
    """
    global _spacy_nlp, _spacy_available
    if _spacy_nlp is not None or _spacy_available is False:
        return _spacy_nlp
    try:
        import spacy
        _spacy_nlp = spacy.load("en_core_web_sm")
        _spacy_available = True
        logger.info("spaCy NER model loaded: en_core_web_sm")
    except OSError:
        # Model not downloaded — instruct user to run:
        #   python -m spacy download en_core_web_sm
        logger.warning(
            "spaCy model 'en_core_web_sm' not found. "
            "Run: python -m spacy download en_core_web_sm  "
            "Falling back to regex entity extraction."
        )
        _spacy_available = False
    except ImportError:
        logger.warning("spaCy not installed. Falling back to regex entity extraction.")
        _spacy_available = False
    return _spacy_nlp


# spaCy labels we care about in a threat-detection context
_SPACY_LABELS_OF_INTEREST = {
    "PERSON",    # named individuals — potential victims / perpetrators
    "ORG",       # organisations — potential targets
    "GPE",       # geopolitical entity (city/country) — potential target location
    "LOC",       # non-GPE location — e.g. "the river", "downtown"
    "FAC",       # facility — "the airport", "Union Station"
    "DATE",      # absolute or relative dates
    "TIME",      # times
    "MONEY",     # monetary values (extortion amounts)
    "QUANTITY",  # counts of people, weapons, etc.
    "CARDINAL",  # bare numbers (e.g. "50 people")
    "NORP",      # nationalities / religions / political groups (terror context)
}


@dataclass
class ThreatResult:
    """Result of NLP threat analysis."""
    threat_detected: bool = False
    threat_type: str = "safe"
    threat_target: str = ""
    threat_description: str = ""
    confidence_score: float = 0.0
    severity: str = "safe"
    intent_score: float = 0.0
    urgency_score: float = 0.0
    keywords_found: List[str] = None
    entities_found: List[Dict] = None
    model_used: str = "hybrid_v1"
    ml_label: str = ""
    ml_confidence: float = 0.0

    def __post_init__(self):
        if self.keywords_found is None:
            self.keywords_found = []
        if self.entities_found is None:
            self.entities_found = []

    def to_dict(self) -> dict:
        return asdict(self)


class NLPThreatEngine:
    """
    Multi-layer NLP engine for detecting threat language in emails.

    Layers:
    1. Keyword/Pattern matching (fast, high recall)
    2. Contextual pattern analysis (phrase-level)
    3. Severity and urgency scoring
    4. Target extraction
    5. Entity extraction — spaCy NER (PERSON/ORG/GPE/LOC/FAC/DATE/TIME/MONEY/QUANTITY)
       with regex fallback when spaCy is unavailable
    6. ML classifier (combines with rules for final score)
    """

    # ===== THREAT LEXICONS =====

    BOMB_THREAT_KEYWORDS = [
        "bomb", "explosive", "detonate", "detonation", "blast", "ied",
        "improvised explosive", "c4", "tnt", "dynamite", "planted bomb",
        "blow up", "blow it up", "explode", "explosion", "kaboom",
        "pipe bomb", "car bomb", "suicide bomb", "vest bomb", "timer bomb",
        "demolition", "bombing", "planted explosives", "rigged to explode",
    ]

    VIOLENCE_THREAT_KEYWORDS = [
        "kill", "murder", "assassinate", "shoot", "shooting", "gun",
        "weapon", "rifle", "pistol", "knife", "stab", "attack",
        "massacre", "slaughter", "execute", "death", "die", "dead",
        "bloodbath", "carnage", "rampage", "mass shooting", "mass killing",
        "sniper", "hostage", "kidnap", "abduct", "harm", "hurt",
    ]

    TERROR_THREAT_KEYWORDS = [
        "terror", "terrorist", "terrorism", "jihad", "infidel",
        "caliphate", "martyr", "martyrdom", "holy war", "crusade",
        "radicalize", "extremist", "insurgent", "militia", "guerrilla",
        "biological weapon", "chemical weapon", "anthrax", "sarin",
        "ricin", "nerve agent", "dirty bomb", "nuclear",
        "weapons of mass destruction", "wmd",
    ]

    EXTORTION_KEYWORDS = [
        "ransom", "pay or else", "bitcoin", "cryptocurrency", "btc",
        "transfer money", "wire transfer", "consequence",
        "expose", "leak", "release information", "blackmail", "extort",
        "demand payment", "pay up", "time is running out",
    ]

    HARASSMENT_KEYWORDS = [
        "harass", "stalk", "threaten", "intimidate", "bully",
        "watch you", "watching you", "following you", "know where you live",
        "your family", "your children", "come for you", "find you",
        "nowhere to hide", "pay for this", "regret this",
    ]

    SCHOOL_THREAT_KEYWORDS = [
        "school shooting", "shoot up the school", "columbine",
        "school attack", "campus threat", "classroom", "students will die",
        "school bomb", "university attack", "campus bomb",
    ]

    # ===== THREAT PHRASES =====

    THREAT_PHRASES = [
        (r"there\s+is\s+a\s+bomb", "bomb_threat", 0.95),
        (r"bomb\s+(?:has\s+been\s+)?planted", "bomb_threat", 0.95),
        (r"(?:will|going\s+to)\s+(?:blow\s+up|explode|detonate)", "bomb_threat", 0.90),
        (r"planted\s+explosives?", "bomb_threat", 0.95),
        (r"explosion\s+will\s+(?:occur|happen)", "bomb_threat", 0.92),
        (r"we\s+have\s+planted", "bomb_threat", 0.93),
        (r"building\s+will\s+(?:be\s+)?(?:destroyed|blown)", "bomb_threat", 0.88),
        (r"(?:i|we)\s+will\s+(?:kill|murder|shoot)\s+(?:you|him|her|them|everyone|people|your|all)", "violence", 0.92),
        (r"(?:going\s+to|gonna)\s+(?:kill|shoot|attack)\s+(?:you|him|her|them|everyone|people)", "violence", 0.90),
        (r"(?:i|we)\s+(?:have|got)\s+(?:a\s+)?(?:gun|weapon|rifle)\s+(?:and|pointed|aimed|ready)", "violence", 0.85),
        (r"mass\s+(?:shooting|killing|murder|casualt)", "violence", 0.93),
        (r"(?:pay|send)\s+(?:\w+\s+)*(?:bitcoin|btc|crypto|money)\s+or", "extortion", 0.88),
        (r"(?:if\s+you\s+don'?t|unless\s+you)\s+(?:pay|send|transfer)", "extortion", 0.85),
        (r"(?:know|found)\s+where\s+you\s+live", "harassment", 0.80),
        (r"coming\s+(?:for|after)\s+you", "harassment", 0.78),
        (r"allahu?\s*akbar.*(?:attack|destroy|kill|bomb)", "terror", 0.90),
        (r"(?:in\s+the\s+name\s+of)\s+(?:allah|god|jihad).*(?:attack|destroy|kill)", "terror", 0.88),
    ]

    TARGET_KEYWORDS = {
        "airport": ["airport", "terminal", "airfield", "runway", "tarmac", "aviation"],
        "school": ["school", "university", "college", "campus", "classroom", "student"],
        "government": ["government", "parliament", "congress", "senate", "embassy", "consulate"],
        "court": ["court", "courthouse", "judge", "trial", "judicial"],
        "hospital": ["hospital", "medical center", "clinic", "emergency room"],
        "mall": ["mall", "shopping center", "shopping centre", "retail"],
        "station": ["train station", "bus station", "metro", "subway", "railway"],
        "bridge": ["bridge", "overpass", "infrastructure"],
        "church": ["church", "mosque", "temple", "synagogue", "worship"],
        "stadium": ["stadium", "arena", "concert", "event venue"],
        "office": ["office building", "corporate", "headquarters", "hq"],
        "military": ["military", "army", "base", "barracks", "navy", "air force"],
    }

    URGENCY_WORDS = {
        "critical": ["now", "immediately", "right now", "this instant", "urgent"],
        "high": ["today", "tonight", "this morning", "this afternoon", "within hours", "soon"],
        "medium": ["tomorrow", "next week", "this week", "coming days"],
        "low": ["someday", "eventually", "one day"],
    }

    HIGH_WEIGHT_KEYWORDS = {
        "ransom", "detonate", "detonation", "ied", "pipe bomb", "car bomb",
        "suicide bomb", "planted bomb", "planted explosives", "there is a bomb",
        "mass shooting", "mass killing", "school shooting", "shoot up the school",
        "students will die", "columbine", "martyrdom", "anthrax", "sarin", "ricin",
        "nerve agent", "dirty bomb", "weapons of mass destruction", "wmd",
        "pay or else", "blackmail", "extort",
    }

    def analyze(self, subject: str, body: str, sender: str = "") -> ThreatResult:
        """
        Perform full NLP + ML threat analysis on email content.
        """
        start_time = time.time()
        combined_text = f"{subject} {body}".strip()
        combined_lower = combined_text.lower()

        if not combined_lower.strip():
            return ThreatResult()

        # Layer 1-5: Rule-based analysis (keyword/phrase use lowercased text)
        keyword_results = self._keyword_analysis(combined_lower)
        phrase_results = self._phrase_analysis(combined_lower)
        urgency_score = self._urgency_analysis(combined_lower)
        targets = self._extract_targets(combined_lower)

        # Layer 5: entity extraction — pass ORIGINAL case text to spaCy for
        # proper NER (named entity recognition is case-sensitive)
        entities = self._extract_entities(combined_text)

        # Layer 6: ML classification
        ml_label, ml_confidence = self._ml_classify(combined_lower)

        # Combine everything
        result = self._combine_results(
            keyword_results, phrase_results, urgency_score,
            targets, entities, ml_label, ml_confidence
        )

        elapsed_ms = int((time.time() - start_time) * 1000)
        logger.info(
            f"NLP+ML analysis completed in {elapsed_ms}ms — "
            f"threat={result.threat_detected}, type={result.threat_type}, "
            f"confidence={result.confidence_score:.2f}, ml={ml_label}({ml_confidence:.2f}), "
            f"entities={len(result.entities_found)}"
        )

        return result

    def _ml_classify(self, text: str) -> Tuple[str, float]:
        """Layer 6: ML model classification."""
        try:
            from app.services.ml_classifier import ml_classifier
            if not ml_classifier.is_available:
                return "unknown", 0.0
            result = ml_classifier.classify(text)
            return result.predicted_label, result.confidence
        except Exception as e:
            logger.warning(f"ML classification skipped: {e}")
            return "unknown", 0.0

    def _keyword_analysis(self, text: str) -> Dict[str, Any]:
        results = {
            "bomb_threat": [], "violence": [], "terror": [],
            "extortion": [], "harassment": [], "school_threat": [],
        }

        def match_keyword(keyword: str, text: str) -> bool:
            if " " in keyword:
                return keyword in text
            return bool(re.search(r'\b' + re.escape(keyword) + r'\b', text))

        for keyword in self.BOMB_THREAT_KEYWORDS:
            if match_keyword(keyword, text):
                results["bomb_threat"].append(keyword)
        for keyword in self.VIOLENCE_THREAT_KEYWORDS:
            if match_keyword(keyword, text):
                results["violence"].append(keyword)
        for keyword in self.TERROR_THREAT_KEYWORDS:
            if match_keyword(keyword, text):
                results["terror"].append(keyword)
        for keyword in self.EXTORTION_KEYWORDS:
            if match_keyword(keyword, text):
                results["extortion"].append(keyword)
        for keyword in self.HARASSMENT_KEYWORDS:
            if match_keyword(keyword, text):
                results["harassment"].append(keyword)
        for keyword in self.SCHOOL_THREAT_KEYWORDS:
            if match_keyword(keyword, text):
                results["school_threat"].append(keyword)

        return results

    def _phrase_analysis(self, text: str) -> List[Tuple[str, str, float]]:
        matches = []
        for pattern, threat_type, confidence in self.THREAT_PHRASES:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append((pattern, threat_type, confidence))
        return matches

    def _urgency_analysis(self, text: str) -> float:
        urgency = 0.0
        for word in self.URGENCY_WORDS["critical"]:
            if word in text:
                urgency = max(urgency, 1.0)
        for word in self.URGENCY_WORDS["high"]:
            if word in text:
                urgency = max(urgency, 0.75)
        for word in self.URGENCY_WORDS["medium"]:
            if word in text:
                urgency = max(urgency, 0.5)
        for word in self.URGENCY_WORDS["low"]:
            if word in text:
                urgency = max(urgency, 0.25)

        excl_count = text.count("!")
        if excl_count >= 3:
            urgency = min(urgency + 0.2, 1.0)

        words = text.split()
        caps_ratio = sum(1 for w in words if w.isupper() and len(w) > 2) / max(len(words), 1)
        if caps_ratio > 0.3:
            urgency = min(urgency + 0.15, 1.0)

        return urgency

    def _extract_targets(self, text: str) -> List[str]:
        found_targets = []
        for target_type, keywords in self.TARGET_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    found_targets.append(target_type)
                    break
        return list(set(found_targets))

    # ------------------------------------------------------------------
    # Layer 5: Entity extraction — spaCy NER with regex fallback
    # ------------------------------------------------------------------

    def _extract_entities(self, text: str) -> List[Dict[str, str]]:
        """
        Extract named entities from email text.

        Primary:  spaCy en_core_web_sm NER — returns PERSON, ORG, GPE, LOC,
                  FAC, DATE, TIME, MONEY, QUANTITY, CARDINAL, NORP entities.
        Fallback: regex-based extraction for DATE, TIME, QUANTITY — used when
                  spaCy is not installed or the model download is missing.

        Each entity dict has keys:
            type  — spaCy label (e.g. "PERSON", "GPE") or regex type
            value — the surface text of the entity
            start — character offset in the original text (spaCy only; -1 for regex)
            end   — character offset end (spaCy only; -1 for regex)
        """
        nlp = _get_spacy()

        if nlp is not None:
            return self._extract_entities_spacy(text, nlp)
        else:
            return self._extract_entities_regex(text)

    def _extract_entities_spacy(self, text: str, nlp) -> List[Dict[str, str]]:
        """spaCy-based NER.  Runs on the original-case text for accuracy."""
        entities: List[Dict[str, str]] = []
        seen: set = set()  # deduplicate by (label, lower-text)

        try:
            # Truncate very long texts to avoid memory spikes on huge emails
            # (spaCy default max is ~1 000 000 chars; we cap at 50 000)
            doc = nlp(text[:50_000])
        except Exception as e:
            logger.warning(f"spaCy NER failed: {e}. Falling back to regex.")
            return self._extract_entities_regex(text)

        for ent in doc.ents:
            if ent.label_ not in _SPACY_LABELS_OF_INTEREST:
                continue

            key = (ent.label_, ent.text.strip().lower())
            if key in seen:
                continue
            seen.add(key)

            entities.append({
                "type": ent.label_,
                "value": ent.text.strip(),
                "start": ent.start_char,
                "end": ent.end_char,
                # Human-readable label for the UI
                "label": self._spacy_label_to_human(ent.label_),
            })

        logger.debug(f"spaCy NER found {len(entities)} entities")
        return entities

    def _extract_entities_regex(self, text: str) -> List[Dict[str, str]]:
        """
        Regex-based entity extraction — used only when spaCy is unavailable.
        Covers DATE, TIME, QUANTITY (same as the old implementation) so
        the rest of the pipeline doesn't break.
        """
        entities: List[Dict[str, str]] = []

        date_patterns = [
            r'\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b',
            r'\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2}(?:,?\s*\d{4})?\b',
            r'\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b',
            r'\b(today|tonight|tomorrow|next\s+(?:week|month|day))\b',
        ]
        for pattern in date_patterns:
            for match in re.findall(pattern, text, re.IGNORECASE):
                entities.append({"type": "DATE", "value": match, "start": -1, "end": -1, "label": "Date"})

        for match in re.findall(r'\b(\d{1,2}:\d{2}\s*(?:am|pm)?)\b', text, re.IGNORECASE):
            entities.append({"type": "TIME", "value": match, "start": -1, "end": -1, "label": "Time"})

        for match in re.findall(r'\b(\d+)\s+(?:people|person|dead|killed|bombs?|explosives?)\b', text, re.IGNORECASE):
            entities.append({"type": "QUANTITY", "value": match, "start": -1, "end": -1, "label": "Quantity"})

        return entities

    @staticmethod
    def _spacy_label_to_human(label: str) -> str:
        """Convert spaCy NER label to a human-readable string for the frontend."""
        return {
            "PERSON":   "Person",
            "ORG":      "Organisation",
            "GPE":      "Location (City/Country)",
            "LOC":      "Location",
            "FAC":      "Facility",
            "DATE":     "Date",
            "TIME":     "Time",
            "MONEY":    "Money",
            "QUANTITY": "Quantity",
            "CARDINAL": "Number",
            "NORP":     "Group/Nationality",
        }.get(label, label)

    def _combine_results(
        self,
        keyword_results: Dict[str, List[str]],
        phrase_results: List[Tuple[str, str, float]],
        urgency_score: float,
        targets: List[str],
        entities: List[Dict],
        ml_label: str,
        ml_confidence: float,
    ) -> ThreatResult:
        """Combine all analysis layers into a final threat assessment."""

        category_scores = {}
        all_keywords = []

        for category, keywords in keyword_results.items():
            if keywords:
                category_scores[category] = len(keywords)
                all_keywords.extend(keywords)

        # Phrase-based type and confidence
        phrase_confidence = 0.0
        phrase_type = None
        for _, threat_type, confidence in phrase_results:
            if confidence > phrase_confidence:
                phrase_confidence = confidence
                phrase_type = threat_type

        # Determine primary type from rules
        if phrase_type and phrase_confidence > 0.8:
            rule_type = phrase_type
        elif category_scores:
            rule_type = max(category_scores, key=category_scores.get)
        else:
            rule_type = "safe"

        # ── Rule-based confidence ──────────────────────────────────
        if phrase_confidence > 0:
            rule_confidence = phrase_confidence
        elif all_keywords:
            keyword_count = len(all_keywords)
            if keyword_count == 1:
                rule_confidence = 0.15
            elif keyword_count == 2:
                rule_confidence = 0.22
            elif keyword_count == 3:
                rule_confidence = 0.42
            else:
                rule_confidence = min(0.42 + ((keyword_count - 3) * 0.10), 0.85)

            if any(kw in self.HIGH_WEIGHT_KEYWORDS for kw in all_keywords):
                rule_confidence = max(rule_confidence, 0.55)
        else:
            rule_confidence = 0.0

        if urgency_score > 0.5 and rule_confidence > 0:
            rule_confidence = min(rule_confidence + 0.05, 0.99)

        # ── Entity-based signal boost ──────────────────────────────
        # Named PERSON + threat keyword = higher intent confidence
        has_named_person = any(e["type"] == "PERSON" for e in entities)
        has_named_location = any(e["type"] in ("GPE", "LOC", "FAC") for e in entities)
        has_money = any(e["type"] == "MONEY" for e in entities)

        if has_named_person and rule_confidence > 0.3:
            # A specific named target strengthens the threat signal
            rule_confidence = min(rule_confidence + 0.06, 0.99)
        if has_named_location and rule_type in ("bomb_threat", "terror", "school_threat") and rule_confidence > 0.3:
            # A named place + threat category → stronger signal
            rule_confidence = min(rule_confidence + 0.05, 0.99)
        if has_money and rule_type == "extortion" and rule_confidence > 0.3:
            # Explicit money amount in extortion email → stronger signal
            rule_confidence = min(rule_confidence + 0.08, 0.99)

        # ── ML-based confidence ────────────────────────────────────
        ml_is_threat = ml_label not in ("safe", "unknown", "")
        ml_weight = 0.35

        if ml_label == "unknown" or ml_confidence == 0:
            final_confidence = rule_confidence
            primary_type = rule_type
            model_used = "rule_based_v1"
        else:
            if ml_is_threat:
                ml_threat_confidence = ml_confidence
            else:
                ml_threat_confidence = 0.0

            final_confidence = (rule_confidence * 0.65) + (ml_threat_confidence * ml_weight)
            final_confidence = round(min(final_confidence, 0.99), 4)

            if ml_is_threat and rule_confidence < 0.3 and ml_confidence > 0.80:
                final_confidence = max(final_confidence, ml_confidence * 0.70)
                primary_type = ml_label
            elif not ml_is_threat and rule_confidence > 0.6 and ml_confidence > 0.75:
                final_confidence = final_confidence * 0.6
                primary_type = rule_type
            else:
                primary_type = rule_type if rule_confidence > 0 else ml_label

            model_used = "hybrid_ml_v2"

        threat_detected = final_confidence >= 0.40

        intent_score = 0.0
        if threat_detected:
            intent_score = min(max(final_confidence * 0.8, 0.0), 1.0)

        if final_confidence >= 0.85:
            severity = "critical"
        elif final_confidence >= 0.65:
            severity = "high"
        elif final_confidence >= 0.45:
            severity = "medium"
        elif final_confidence >= 0.3:
            severity = "low"
        else:
            severity = "safe"

        description = self._generate_description(primary_type, all_keywords, targets, final_confidence)
        target_str = ", ".join(targets) if targets else ""

        return ThreatResult(
            threat_detected=threat_detected,
            threat_type=primary_type,
            threat_target=target_str,
            threat_description=description,
            confidence_score=round(final_confidence, 4),
            severity=severity,
            intent_score=round(intent_score, 4),
            urgency_score=round(urgency_score, 4),
            keywords_found=list(set(all_keywords)),
            entities_found=entities,
            model_used=model_used,
            ml_label=ml_label,
            ml_confidence=round(ml_confidence, 4),
        )

    def _generate_description(self, threat_type, keywords, targets, confidence) -> str:
        if not keywords and not threat_type:
            return "No threat indicators detected in this email."

        type_labels = {
            "bomb_threat": "Bomb/Explosive Threat",
            "violence": "Violence Threat",
            "terror": "Terror-Related Threat",
            "extortion": "Extortion/Blackmail",
            "harassment": "Harassment/Intimidation",
            "school_threat": "School Threat",
            "safe": "No Threat Detected",
        }

        label = type_labels.get(threat_type, "Unknown Threat")
        target_str = f" targeting {', '.join(targets)}" if targets else ""
        keyword_str = ", ".join(list(set(keywords))[:5]) if keywords else "ML pattern detection"

        return (
            f"{label} detected{target_str} with {confidence:.0%} confidence. "
            f"Key indicators: {keyword_str}."
        )


# Singleton instance
nlp_engine = NLPThreatEngine()