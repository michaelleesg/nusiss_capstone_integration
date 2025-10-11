import json


def check_logs(path="rai/log_example.jsonl"):
    lines = [json.loads(l) for l in open(path)]
    assert any("entity" in d for d in lines)
    assert any("action" in d for d in lines)


if __name__ == "__main__":
    check_logs()
