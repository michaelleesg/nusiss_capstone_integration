from transformers import AutoTokenizer, AutoModelForTokenClassification, DataCollatorForTokenClassification, TrainingArguments, Trainer
from datasets import Dataset
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Read file directly instead of load_dataset
data_path = "ner_training.txt"
if not os.path.exists(data_path):
    raise FileNotFoundError(f"Missing training data file: {data_path}")

tokens, tags = [], []
sentences = []

with open(data_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            if tokens:
                sentences.append({"tokens": tokens, "ner_tags": tags})
                tokens, tags = [], []
        else:
            parts = line.split("\t")
            if len(parts) == 2:
                tokens.append(parts[0])
                tags.append(parts[1])
            else:
                print(f"⚠️ Skipped malformed line: {line}")

# Catch final sentence if file doesn't end with newline
if tokens:
    sentences.append({"tokens": tokens, "ner_tags": tags})

print(f"✅ Parsed {len(sentences)} sentence examples from ner_training.txt")
if len(sentences) == 0:
    raise ValueError("❌ No valid sentence found. Check ner_training.txt formatting.")

# Build dataset and label map
dataset = Dataset.from_list(sentences)
unique_tags = sorted({tag for example in sentences for tag in example["ner_tags"]})
tag2id = {tag: i for i, tag in enumerate(unique_tags)}
id2tag = {i: tag for tag, i in tag2id.items()}

# Add numeric labels
dataset = dataset.map(lambda x: {"labels": [tag2id[t] for t in x["ner_tags"]]})

# Tokenizer and alignment
tokenizer = AutoTokenizer.from_pretrained("bert-base-cased")

def tokenize_and_align_labels(example):
    tokenized_inputs = tokenizer(
        example["tokens"],
        truncation=True,
        padding="max_length",
        is_split_into_words=True,
        return_tensors=None,
        max_length=128
    )
    word_ids = tokenized_inputs.word_ids()

    aligned_labels = []
    previous_word_idx = None
    for word_idx in word_ids:
        if word_idx is None:
            aligned_labels.append(-100)
        elif word_idx != previous_word_idx:
            aligned_labels.append(example["labels"][word_idx])
        else:
            aligned_labels.append(-100)
        previous_word_idx = word_idx

    tokenized_inputs["labels"] = aligned_labels
    return tokenized_inputs

tokenized_dataset = dataset.map(tokenize_and_align_labels)

# ✅ Preserve "labels" for validation, only drop unused fields
tokenized_dataset = tokenized_dataset.remove_columns(["tokens", "ner_tags"])

# Count usable samples
valid_count = sum(1 for x in tokenized_dataset if any(l != -100 for l in x["labels"]))
print(f"✅ Usable training samples after tokenization: {valid_count}")
if valid_count == 0:
    raise ValueError("❌ All labels masked after tokenization. Check alignment.")

# Load model and train
model = AutoModelForTokenClassification.from_pretrained(
    "bert-base-cased", num_labels=len(tag2id), id2label=id2tag, label2id=tag2id
)

args = TrainingArguments(
    output_dir="ner_model",
    per_device_train_batch_size=2,
    num_train_epochs=3,
    logging_steps=1,
    save_steps=5,
    remove_unused_columns=False
)

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=tokenized_dataset,
    tokenizer=tokenizer,
    data_collator=DataCollatorForTokenClassification(tokenizer),
)

trainer.train()
