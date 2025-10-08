# Hybrid extractor stub
import spacy
from .regex_patterns import CVE_PATTERN, IP_PATTERN, DOMAIN_PATTERN

class HybridExtractor:
    def __init__(self, model="en_core_web_trf"):
        self.nlp = spacy.load(model)
    def extract(self, text):
        doc = self.nlp(text)
        entities = [{"text":ent.text, "label":ent.label_, "confidence":1.0} for ent in doc.ents]
        for pat,label in [(CVE_PATTERN,"CVE"), (IP_PATTERN,"IP"), (DOMAIN_PATTERN,"DOMAIN")]:
            for m in pat.finditer(text):
                entities.append({"text": m.group(), "label": label, "confidence": 1.0})
        return entities
