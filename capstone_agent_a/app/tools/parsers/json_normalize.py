"""JSON normalization tool."""

import json
import logging
from typing import Any, Dict

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class JSONNormalizeInput(BaseModel):
    """Input for JSON normalizer."""

    obj: Any = Field(description="JSON object to normalize")


class JSONNormalizeOutput(BaseModel):
    """Output for JSON normalizer."""

    text: str = Field(description="Readable text representation")
    flat: Dict[str, Any] = Field(description="Flattened key-value pairs")


def flatten_json(obj: Any, parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Flatten nested JSON object into dot-notation keys."""
    items = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, (dict, list)):
                items.extend(flatten_json(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))

    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            if isinstance(v, (dict, list)):
                items.extend(flatten_json(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
    else:
        return {parent_key: obj}

    return dict(items)


def json_to_readable_text(obj: Any, depth: int = 0, max_depth: int = 10) -> str:
    """Convert JSON object to readable text."""
    if depth > max_depth:
        return "[Max depth reached]"

    indent = "  " * depth

    if isinstance(obj, dict):
        if not obj:
            return "{}"

        lines = ["{"]
        for i, (key, value) in enumerate(obj.items()):
            if i > 50:  # Limit number of items shown
                lines.append(f"{indent}  ... ({len(obj) - 50} more items)")
                break

            value_text = json_to_readable_text(value, depth + 1, max_depth)
            lines.append(f"{indent}  {key}: {value_text}")

        lines.append(f"{indent}}}")
        return "\n".join(lines)

    elif isinstance(obj, list):
        if not obj:
            return "[]"

        if len(obj) > 20:  # For long lists, show sample and summary
            sample_items = obj[:10]
            lines = [f"[Array with {len(obj)} items, showing first 10:]"]
            for i, item in enumerate(sample_items):
                item_text = json_to_readable_text(item, depth + 1, max_depth)
                lines.append(f"{indent}  [{i}]: {item_text}")
            lines.append(f"{indent}  ... {len(obj) - 10} more items")
            return "\n".join(lines)
        else:
            lines = ["["]
            for i, item in enumerate(obj):
                item_text = json_to_readable_text(item, depth + 1, max_depth)
                lines.append(f"{indent}  [{i}]: {item_text}")
            lines.append(f"{indent}]")
            return "\n".join(lines)

    elif isinstance(obj, str):
        # Truncate very long strings
        if len(obj) > 200:
            return f'"{obj[:200]}..."'
        else:
            return f'"{obj}"'

    elif obj is None:
        return "null"

    elif isinstance(obj, bool):
        return "true" if obj else "false"

    else:
        return str(obj)


def extract_key_info(obj: Any) -> str:
    """Extract key information from JSON for summary."""
    info_parts = []

    if isinstance(obj, dict):
        # Look for common informative keys
        key_fields = [
            "title", "name", "subject", "info", "description",
            "summary", "message", "content", "data"
        ]

        for field in key_fields:
            if field in obj:
                value = obj[field]
                if isinstance(value, str) and value.strip():
                    info_parts.append(f"{field}: {value[:100]}...")
                    break

        # Add type information if available
        if "type" in obj:
            info_parts.append(f"type: {obj['type']}")

        # Add count information
        if "count" in obj or "length" in obj:
            count = obj.get("count", obj.get("length"))
            info_parts.append(f"count: {count}")

    elif isinstance(obj, list):
        info_parts.append(f"Array with {len(obj)} items")
        if obj and isinstance(obj[0], dict):
            # Try to describe the structure of array items
            first_item = obj[0]
            if "type" in first_item:
                info_parts.append(f"items of type: {first_item['type']}")

    return " | ".join(info_parts) if info_parts else "No key information found"


def json_normalize(input_data: JSONNormalizeInput) -> JSONNormalizeOutput:
    """Normalize JSON object to text and flattened structure."""
    try:
        obj = input_data.obj

        # Generate readable text
        readable_text = json_to_readable_text(obj)

        # Add summary information
        summary = extract_key_info(obj)
        if summary != "No key information found":
            readable_text = f"Summary: {summary}\n\n{readable_text}"

        # Flatten the object
        flat_obj = flatten_json(obj)

        # Limit flattened object size
        if len(flat_obj) > 1000:
            logger.warning(f"Large flattened object: {len(flat_obj)} keys, truncating")
            # Keep the most important looking keys
            important_keys = []
            other_keys = []

            for key in flat_obj.keys():
                if any(important in key.lower() for important in [
                    "title", "name", "type", "id", "description", "summary",
                    "url", "link", "date", "time", "value", "content"
                ]):
                    important_keys.append(key)
                else:
                    other_keys.append(key)

            # Take up to 500 important keys + 500 others
            selected_keys = important_keys[:500] + other_keys[:500]
            flat_obj = {k: flat_obj[k] for k in selected_keys}

        logger.info(
            f"Normalized JSON: {len(readable_text)} chars text, "
            f"{len(flat_obj)} flattened keys"
        )

        return JSONNormalizeOutput(
            text=readable_text,
            flat=flat_obj
        )

    except Exception as e:
        logger.error(f"Error normalizing JSON: {e}")
        return JSONNormalizeOutput(
            text=f"Error normalizing JSON: {str(e)}",
            flat={"error": str(e)}
        )


# Tool registration for MCP
TOOL_NAME = "json.normalize"
TOOL_DESCRIPTION = "Convert JSON object to readable text and flattened structure"
INPUT_SCHEMA = JSONNormalizeInput.model_json_schema()
OUTPUT_SCHEMA = JSONNormalizeOutput.model_json_schema()