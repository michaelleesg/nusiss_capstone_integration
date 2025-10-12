"""MISP event parser."""

import json
import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class MISPParseInput(BaseModel):
    """Input for MISP parser."""

    json_data: Dict[str, Any] = Field(description="MISP JSON data", alias="json")


class MISPParseOutput(BaseModel):
    """Output for MISP parser."""

    event: Dict[str, Any] = Field(description="Parsed event object")
    attributes: List[Dict[str, Any]] = Field(description="Extracted attributes")
    tags: List[str] = Field(description="Event tags")
    title: Optional[str] = Field(description="Event title/info")
    description: Optional[str] = Field(description="Event description")


def parse_misp_attributes(attributes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse MISP attributes with normalization."""
    parsed = []

    for attr in attributes:
        if not isinstance(attr, dict):
            continue

        try:
            parsed_attr = {
                "category": attr.get("category", ""),
                "type": attr.get("type", ""),
                "value": attr.get("value", ""),
                "comment": attr.get("comment", ""),
                "to_ids": attr.get("to_ids", False),
                "uuid": attr.get("uuid", ""),
                "timestamp": attr.get("timestamp", "")
            }

            # Include object relation if present
            if "object_relation" in attr:
                parsed_attr["object_relation"] = attr["object_relation"]

            parsed.append(parsed_attr)

        except Exception as e:
            logger.warning(f"Error parsing MISP attribute: {e}")
            continue

    return parsed


def parse_misp_tags(tags: List[Any]) -> List[str]:
    """Parse MISP tags."""
    parsed_tags = []

    for tag in tags:
        try:
            if isinstance(tag, dict):
                name = tag.get("name", "")
                if name:
                    parsed_tags.append(name)
            elif isinstance(tag, str):
                parsed_tags.append(tag)
        except Exception as e:
            logger.warning(f"Error parsing MISP tag: {e}")

    return parsed_tags


def parse_misp_objects(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse MISP objects and extract their attributes."""
    all_attributes = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        try:
            obj_attributes = obj.get("Attribute", [])
            if isinstance(obj_attributes, list):
                # Add object context to attributes
                for attr in obj_attributes:
                    if isinstance(attr, dict):
                        attr["object_name"] = obj.get("name", "")
                        attr["object_template_uuid"] = obj.get("template_uuid", "")

                all_attributes.extend(obj_attributes)

        except Exception as e:
            logger.warning(f"Error parsing MISP object: {e}")

    return all_attributes


def misp_parse_event(input_data: MISPParseInput) -> MISPParseOutput:
    """Parse MISP event JSON."""
    try:
        data = input_data.json_data

        # Handle different MISP JSON structures
        if "Event" in data:
            event = data["Event"]
        elif "events" in data and isinstance(data["events"], list) and data["events"]:
            event = data["events"][0]
        else:
            event = data

        if not isinstance(event, dict):
            raise ValueError("Invalid MISP event structure")

        # Extract basic event info
        title = event.get("info", "")
        description = event.get("comment", "")

        # Parse attributes
        attributes = []
        event_attributes = event.get("Attribute", [])
        if isinstance(event_attributes, list):
            attributes.extend(parse_misp_attributes(event_attributes))

        # Parse objects (which contain more attributes)
        objects = event.get("Object", [])
        if isinstance(objects, list):
            object_attributes = parse_misp_objects(objects)
            attributes.extend(parse_misp_attributes(object_attributes))

        # Parse tags
        tags = []
        event_tags = event.get("Tag", [])
        if isinstance(event_tags, list):
            tags = parse_misp_tags(event_tags)

        # Also check for EventTag structure
        event_tags_alt = event.get("EventTag", [])
        if isinstance(event_tags_alt, list):
            for event_tag in event_tags_alt:
                if isinstance(event_tag, dict) and "Tag" in event_tag:
                    tag_obj = event_tag["Tag"]
                    if isinstance(tag_obj, dict) and "name" in tag_obj:
                        tags.append(tag_obj["name"])

        logger.info(
            f"Parsed MISP event: {len(attributes)} attributes, "
            f"{len(tags)} tags, title: {title[:50]}..."
        )

        return MISPParseOutput(
            event=event,
            attributes=attributes,
            tags=tags,
            title=title if title else None,
            description=description if description else None
        )

    except Exception as e:
        logger.error(f"Error parsing MISP event: {e}")
        # Return empty structure on error
        return MISPParseOutput(
            event={},
            attributes=[],
            tags=[],
            title=None,
            description=None
        )


# Tool registration for MCP
TOOL_NAME = "misp.parse_event"
TOOL_DESCRIPTION = "Parse MISP event JSON and extract structured data"
INPUT_SCHEMA = MISPParseInput.model_json_schema()
OUTPUT_SCHEMA = MISPParseOutput.model_json_schema()