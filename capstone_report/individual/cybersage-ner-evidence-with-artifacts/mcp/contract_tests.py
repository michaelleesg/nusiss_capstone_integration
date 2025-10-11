import json, glob
from jsonschema import validate

schema = json.load(open("mcp/schema.json"))


def test_traces():
    for path in glob.glob("mcp/traces/*.json"):
        msg = json.load(open(path))
        validate(instance=msg, schema=schema)
