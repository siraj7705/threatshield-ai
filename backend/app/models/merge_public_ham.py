# LOCATION: backend/ml_models/merge_public_ham.py
"""
Blends real SpamAssassin ham emails into training_data.json.

Two modes:
  1. AUTO: downloads ~250 ham from a GitHub-hosted SMS corpus (fallback)
  2. LOCAL: reads from the SpamAssassin archive you provide

Usage:
    # With the archive.zip you downloaded:
    python ml_models/merge_public_ham.py --archive /path/to/archive.zip

    # Without the archive (falls back to SMS corpus):
    python ml_models/merge_public_ham.py

Run AFTER generate_dataset.py, BEFORE train.py.
"""

import argparse
import email
import io
import json
import os
import random
import re
import sys
import zipfile
from pathlib import Path

DATASET_PATH = Path(__file__).parent / "training_data.json"
N_HAM = 220          # how many ham emails to blend in
MIN_BODY_LEN = 40    # skip near-empty bodies
MAX_BODY_LEN = 500   # truncate very long bodies to first N chars


# ─── Email body extraction ────────────────────────────────────────────────────

def extract_body(raw: bytes) -> str:
    """Parse a raw email file and return just the plain-text body."""
    try:
        msg = email.message_from_bytes(raw)
    except Exception:
        return ""

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    break
                except Exception:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
        except Exception:
            body = str(msg.get_payload())

    # Strip quoted reply chains (lines starting with >)
    lines = [l for l in body.splitlines() if not l.startswith(">")]
    body = " ".join(lines)

    # Collapse whitespace
    body = re.sub(r"\s+", " ", body).strip()

    # Truncate
    return body[:MAX_BODY_LEN]


# ─── Source: SpamAssassin archive.zip ────────────────────────────────────────

def load_from_archive(archive_path: str, n: int) -> list[str]:
    """Extract ham bodies from the SpamAssassin zip archive."""
    print(f"Reading SpamAssassin archive: {archive_path}")
    bodies = []

    with zipfile.ZipFile(archive_path) as zf:
        names = zf.namelist()
        # Ham folders: easy_ham and hard_ham (not __MACOSX, not spam_2)
        ham_names = [
            n for n in names
            if ("easy_ham" in n or "hard_ham" in n)
            and "__MACOSX" not in n
            and not n.endswith("/")
        ]
        print(f"  Found {len(ham_names)} ham email files")

        random.seed(42)
        random.shuffle(ham_names)

        for name in ham_names:
            raw = zf.read(name)
            body = extract_body(raw)
            if len(body) >= MIN_BODY_LEN:
                bodies.append(body)
            if len(bodies) >= n:
                break

    print(f"  Extracted {len(bodies)} usable bodies")
    return bodies


# ─── Fallback: SMS Spam Collection (GitHub) ──────────────────────────────────

def load_from_sms(n: int) -> list[str]:
    import urllib.request, csv

    url = (
        "https://raw.githubusercontent.com/"
        "mohitgupta-omg/Kaggle-SMS-Spam-Collection-Dataset-/master/spam.csv"
    )
    print(f"Downloading SMS ham corpus from GitHub (fallback)...")
    with urllib.request.urlopen(url) as resp:
        raw = resp.read().decode("latin-1")

    reader = csv.reader(io.StringIO(raw))
    next(reader)
    hams = [row[1].strip() for row in reader
            if len(row) >= 2 and row[0].strip() == "ham" and len(row[1].strip()) >= MIN_BODY_LEN]

    random.seed(42)
    random.shuffle(hams)
    selected = hams[:n]
    print(f"  Selected {len(selected)} SMS ham messages")
    return selected


# ─── Main ─────────────────────────────────────────────────────────────────────

def merge(archive_path: str | None):
    if not DATASET_PATH.exists():
        sys.exit(f"Dataset not found: {DATASET_PATH}\nRun generate_dataset.py first.")

    with open(DATASET_PATH) as f:
        data = json.load(f)

    # Remove previously merged public ham
    before = len(data)
    data = [d for d in data if d.get("source") != "public_ham"]
    if before != len(data):
        print(f"Removed {before - len(data)} previously merged ham entries")

    # Load ham
    if archive_path:
        bodies = load_from_archive(archive_path, N_HAM)
    else:
        bodies = load_from_sms(N_HAM)

    for text in bodies:
        data.append({"text": text, "label": "safe", "source": "public_ham"})

    random.seed(42)
    random.shuffle(data)

    with open(DATASET_PATH, "w") as f:
        json.dump(data, f, indent=2)

    from collections import Counter
    counts = Counter(d["label"] for d in data)
    print(f"\nDataset after merge — {len(data)} total samples:")
    labels = ["safe", "bomb_threat", "violence", "terror", "extortion", "harassment", "school_threat"]
    for label in labels:
        print(f"  {label}: {counts.get(label, 0)}")
    public = sum(1 for d in data if d.get("source") == "public_ham")
    print(f"  (of which {public} safe entries are real SpamAssassin/public ham)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", help="Path to archive.zip (SpamAssassin corpus)")
    args = parser.parse_args()
    merge(args.archive)
    print("\nDone. Now run: python ml_models/train.py")