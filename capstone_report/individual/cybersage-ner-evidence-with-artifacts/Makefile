PY=python

.PHONY: eval ablate bench mcp security rai all

eval:
	$(PY) ner/evaluate.py --model ./model-best --gold data/annotations/test.jsonl --out_dir artifacts/

ablate:
	$(PY) ner/evaluate.py --model ./models/ml_only --gold data/annotations/test.jsonl --out_dir artifacts/ml_only
	$(PY) ner/evaluate.py --model ./models/regex_only --gold data/annotations/test.jsonl --out_dir artifacts/regex_only
	$(PY) ner/evaluate.py --model ./models/hybrid --gold data/annotations/test.jsonl --out_dir artifacts/hybrid

bench:
	$(PY) qdrant_bench/bench_search.py > artifacts/qdrant_bench.json

mcp:
	pytest mcp/contract_tests.py -q

security:
	pytest security/test_security.py -q

rai:
	$(PY) rai/rai_checks.py

all: eval ablate bench mcp security rai
