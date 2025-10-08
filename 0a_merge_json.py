import json
import uuid
import os

# ✅ Define paths
base_dir = "C:/Users/mike/Downloads/capstone"
file1 = os.path.join(base_dir, "Article_Storage.Article_Collection_2025.json")
file2 = os.path.join(base_dir, "Raw_Crawled_Fixed.json")
output_path = os.path.join(base_dir, "combined.json")

# ✅ Load first file
with open(file1, "r", encoding="utf-8") as f1:
    data1 = json.load(f1)

# ✅ Load second file
with open(file2, "r", encoding="utf-8") as f2:
    data2 = json.load(f2)

# 🧹 Flatten nested lists if present
flat_data1 = []
for entry in data1:
    if isinstance(entry, list):
        flat_data1.extend(entry)
    elif isinstance(entry, dict):
        flat_data1.append(entry)

flat_data2 = []
for entry in data2:
    if isinstance(entry, list):
        flat_data2.extend(entry)
    elif isinstance(entry, dict):
        flat_data2.append(entry)

# 🧠 De-duplicate IDs by regenerating conflicting ones
existing_ids = set()
for item in flat_data1:
    if "_id" in item:
        existing_ids.add(item["_id"])

for item in flat_data2:
    if isinstance(item, dict):
        original_id = item.get("_id", str(uuid.uuid4()))
        while item.get("_id") in existing_ids or not isinstance(item.get("_id"), str):
            item["_id"] = str(uuid.uuid4())
        existing_ids.add(item["_id"])
    else:
        print(f"⚠️ Skipped malformed entry (not a dict): {item}")

# 📝 Merge and save
combined = flat_data1 + flat_data2
with open(output_path, "w", encoding="utf-8") as out:
    json.dump(combined, out, indent=2, ensure_ascii=False)

print(f"✅ Merged {len(flat_data1)} + {len(flat_data2)} entries → {output_path}")
