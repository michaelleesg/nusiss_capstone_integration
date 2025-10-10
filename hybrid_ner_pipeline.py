import json
import re
from bs4 import BeautifulSoup
import pandas as pd
from nltk.tokenize import sent_tokenize
from sentence_transformers import SentenceTransformer


def clean_html(raw_html):
    soup = BeautifulSoup(raw_html, "html.parser")
    return soup.get_text()


def extract_sentences(text):
    return sent_tokenize(text)


def extract_rule_based_entities(text):
    return {
        "cve_ids": re.findall(r"CVE-\d{4}-\d+", text),
        "malware": re.findall(r"\b[A-Z][a-zA-Z0-9]+\b(?:[A-Z][a-zA-Z0-9]*)?", text),
        "threat_actors": re.findall(r"\bAPT\d+\b|\bTA\d+\b", text),
    }


def extract_prompt_entities(text):
    threat_actors = re.findall(
        r"(APT\d+|TA\d+|Cozy Bear|Molerats|Gaza Cyber Gang|Arid Viper)", text
    )
    sectors = re.findall(
        r"(Media|Government|Energy|Defense|Communication Services)", text
    )
    motives = re.findall(r"(Espionage|Retaliation|Disinformation)", text)
    victims = re.findall(r"(Azerbaijani Media Outlets|Baku TV|Middle East)", text)
    return {
        "threat_actors_prompt": list(set(threat_actors)),
        "sectors_prompt": list(set(sectors)),
        "motives_prompt": list(set(motives)),
        "victims_prompt": list(set(victims)),
    }


def vectorize_entities(entity_dict, model):
    vector_data = []
    for key, values in entity_dict.items():
        for val in values:
            vector = model.encode(val)
            vector_data.append(
                {"entity_type": key, "entity": val, "vector": vector.tolist()}
            )
    return vector_data


def run_pipeline(input_json_path):
    with open(input_json_path, "r") as f:
        records = json.load(f)

    model = SentenceTransformer("all-MiniLM-L6-v2")
    all_output = []

    for record in records:
        text = record.get("text", "") + " " + record.get("markdown", "")
        clean = clean_html(text)

        rule_ents = extract_rule_based_entities(clean)
        prompt_ents = extract_prompt_entities(clean)
        combined_entities = {**rule_ents, **prompt_ents}

        vectors = vectorize_entities(combined_entities, model)

        for v in vectors:
            v["source_url"] = record.get("_id") or record.get("assessment", {}).get(
                "url"
            )
            v["article_date"] = record.get("date_time") or record.get(
                "assessment", {}
            ).get("title")
        all_output.extend(vectors)

    return all_output


if __name__ == "__main__":
    result = run_pipeline("combined.json")
    df = pd.DataFrame(result)
    df.to_csv("ner_vector_output.csv", index=False)
    print("✅ Output saved to ner_vector_output.csv")
