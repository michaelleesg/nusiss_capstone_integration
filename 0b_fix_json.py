import json
import re
import ast
import os

# from pathlib import Path
# BASE = Path(__file__).resolve().parents[0]
# INPUT = Path(os.environ.get("CYBERSAGE_INPUT", BASE/"data"/"Raw_Crawled_Fixed.json"))


input_path = "C:/Users/mike/Downloads/capstone/Raw_Crawled_Data_With_LLM.json"
output_path = "C:/Users/mike/Downloads/capstone/Raw_Crawled_Fixed.json"


def fix_quotes_and_formatting(raw_text):
    # Fix keys: foo: → "foo":
    raw_text = re.sub(r'(?<!")(?P<key>\b\w+)\s*:', r'"\g<key>":', raw_text)

    # Fix common Python booleans and None
    raw_text = (
        raw_text.replace("None", "null")
        .replace("True", "true")
        .replace("False", "false")
    )

    # Remove trailing commas before } or ]
    raw_text = re.sub(r",(\s*[}\]])", r"\1", raw_text)

    # Remove inline comments
    raw_text = re.sub(r"#.*", "", raw_text)

    return raw_text.strip()


def parse_line(line, index):
    line = fix_quotes_and_formatting(line)

    # Try as strict JSON
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        pass

    # Try relaxed Python-style dict using ast
    try:
        return ast.literal_eval(line)
    except Exception as e:
        print(f"❌ Still broken at index {index}: {e}")
        return None


with open(input_path, "r", encoding="utf-8") as f:
    lines = f.read().strip().splitlines()

fixed_records = []
for i, line in enumerate(lines):
    if not line.strip():
        continue
    obj = parse_line(line.strip(), i)
    if obj:
        fixed_records.append(obj)

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(fixed_records, f, indent=2, ensure_ascii=False)

print(f"✅ Fixed and saved {len(fixed_records)} valid records to {output_path}")
