import logging
import json
import re
import spacy
from pathlib import Path
import os

# === Config ===

# from pathlib import Path
# BASE = Path(__file__).resolve().parents[0]
# INPUT = Path(os.environ.get("CYBERSAGE_INPUT", BASE/"data"/"Raw_Crawled_Fixed.json"))

INPUT_FILE = "C:/Users/mike/Downloads/capstone/combined.json"
OUTPUT_BIO = "C:/Users/mike/Downloads/capstone/ner_training.txt"
CHECKPOINT_FILE = "C:/Users/mike/Downloads/capstone/checkpoint.json"


# INPUT_FILE = "C:/Users/mike/Downloads/capstone/combined.json"
# OUTPUT_BIO = "C:/Users/mike/Downloads/capstone/ner_training.txt"
# CHECKPOINT_FILE = "C:/Users/mike/Downloads/capstone/checkpoint.json"
# === Logging Setup ===
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("NER_Preprocessor")

# === Load spaCy NER model ===
try:
    nlp = spacy.load("en_core_web_sm")
    logger.info("✅ Loaded spaCy model 'en_core_web_sm'")
except OSError:
    logger.error(
        "❌ spaCy model 'en_core_web_sm' not found. Run: python -m spacy download en_core_web_sm"
    )
    raise

# === Rule-based patterns ===
RULE_PATTERNS = {
    "CVE": r"\bCVE-\d{4}-\d{4,7}\b",
    "EMAIL": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
    "IP": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "URL": r"http[s]?://[^\s\"']+",
}


def extract_sentences(text):
    return [sent.text.strip() for sent in nlp(text).sents if sent.text.strip()]


def apply_rule_based(text):
    spans = []
    for label, pattern in RULE_PATTERNS.items():
        for match in re.finditer(pattern, text):
            spans.append((match.start(), match.end(), label))
    return spans


def get_combined_entities(text):
    doc = nlp(text)
    spans = [(ent.start_char, ent.end_char, ent.label_) for ent in doc.ents]
    spans += apply_rule_based(text)
    spans.sort(key=lambda x: x[0])
    final_spans = []
    last_end = -1
    for start, end, label in spans:
        if start >= last_end:
            final_spans.append((start, end, label))
            last_end = end
    return final_spans


def tokenize_bio_by_words(sentence, entity_spans):
    doc = nlp(sentence)
    tokens = [token.text for token in doc]
    tags = ["O"] * len(tokens)
    for start, end, label in entity_spans:
        for i, token in enumerate(doc):
            token_start = token.idx
            token_end = token.idx + len(token.text)
            if token_start >= start and token_end <= end:
                tags[i] = f"I-{label}"
                if token_start == start:
                    tags[i] = f"B-{label}"
    return list(zip(tokens, tags))


def load_checkpoint():
    if Path(CHECKPOINT_FILE).exists():
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f).get("last_index", 0)
    return 0


def save_checkpoint(index):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({"last_index": index}, f)


def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    total = len(data)
    logger.info(f"📂 Loaded {total} entries from {INPUT_FILE}")

    start_index = load_checkpoint()
    logger.info(f"⏱️ Resuming from index {start_index}")

    all_sentences = []
    skipped = 0

    def process_range(start, end):
        nonlocal skipped
        for i in range(start, end):
            item = data[i]
            if not isinstance(item, dict):
                logger.warning(
                    f"⚠️ Skipped non-dict entry at index {i}: {str(item)[:100]}"
                )
                skipped += 1
                continue

            text = item.get("text") or item.get("content") or ""
            if not isinstance(text, str) or not text.strip():
                logger.warning(f"⚠️ Skipped empty or non-string text at index {i}")
                skipped += 1
                continue

            for sentence in extract_sentences(text):
                entity_spans = get_combined_entities(sentence)
                bio_tagged = tokenize_bio_by_words(sentence, entity_spans)
                if bio_tagged:
                    all_sentences.append(bio_tagged)

            save_checkpoint(i)

            if (i + 1) % 500 == 0:
                logger.info(f"🧠 Processed {i + 1}/{total} items...")

    logger.info("🔁 Pass 1: From checkpoint to end")
    process_range(start_index, total)

    if start_index > 0:
        logger.info("🔁 Pass 2: From start to checkpoint-1")
        process_range(0, start_index)

    with open(OUTPUT_BIO, "w", encoding="utf-8") as f:
        for sent in all_sentences:
            for token, tag in sent:
                f.write(f"{token} {tag}\n")
            f.write("\n")

    logger.info(f"✅ Done! BIO-tagged {len(all_sentences)} sentences to {OUTPUT_BIO}")
    logger.info(f"📉 Skipped {skipped} malformed or empty entries")


if __name__ == "__main__":
    main()
