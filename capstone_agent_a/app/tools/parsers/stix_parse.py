"""STIX bundle parser using python-stix2 library."""

import json
import logging
from typing import Any, Dict, List, Optional

import stix2
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class STIXParseInput(BaseModel):
    """Input for STIX parser."""

    json_data: Dict[str, Any] = Field(description="STIX JSON data", alias="json")


class STIXParseOutput(BaseModel):
    """Output for STIX parser."""

    objects: List[Dict[str, Any]] = Field(description="STIX domain objects")
    relationships: List[Dict[str, Any]] = Field(description="STIX relationships")
    report: Optional[Dict[str, Any]] = Field(description="Main report object if present")


def extract_stix_relationships(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract relationship objects."""
    relationships = []

    for obj in objects:
        if isinstance(obj, dict) and obj.get("type") == "relationship":
            try:
                relationship = {
                    "id": obj.get("id", ""),
                    "relationship_type": obj.get("relationship_type", ""),
                    "source_ref": obj.get("source_ref", ""),
                    "target_ref": obj.get("target_ref", ""),
                    "created": obj.get("created", ""),
                    "modified": obj.get("modified", "")
                }

                # Include description if present
                if "description" in obj:
                    relationship["description"] = obj["description"]

                relationships.append(relationship)

            except Exception as e:
                logger.warning(f"Error parsing STIX relationship: {e}")

    return relationships


def filter_stix_domain_objects(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter and clean domain objects (non-meta objects)."""
    domain_objects = []

    # Define STIX Domain Object types (excluding meta objects and relationships)
    domain_types = {
        "attack-pattern",
        "campaign",
        "course-of-action",
        "grouping",
        "identity",
        "indicator",
        "infrastructure",
        "intrusion-set",
        "location",
        "malware",
        "malware-analysis",
        "note",
        "observed-data",
        "opinion",
        "report",
        "threat-actor",
        "tool",
        "vulnerability"
    }

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        obj_type = obj.get("type", "")
        if obj_type in domain_types:
            try:
                # Extract common fields
                cleaned_obj = {
                    "type": obj_type,
                    "id": obj.get("id", ""),
                    "created": obj.get("created", ""),
                    "modified": obj.get("modified", ""),
                }

                # Add type-specific fields
                if "name" in obj:
                    cleaned_obj["name"] = obj["name"]

                if "description" in obj:
                    cleaned_obj["description"] = obj["description"]

                if "labels" in obj:
                    cleaned_obj["labels"] = obj["labels"]

                # Indicator-specific fields
                if obj_type == "indicator":
                    if "pattern" in obj:
                        cleaned_obj["pattern"] = obj["pattern"]
                    if "indicator_types" in obj:
                        cleaned_obj["indicator_types"] = obj["indicator_types"]

                # Malware-specific fields
                if obj_type == "malware":
                    if "is_family" in obj:
                        cleaned_obj["is_family"] = obj["is_family"]
                    if "malware_types" in obj:
                        cleaned_obj["malware_types"] = obj["malware_types"]

                # Threat Actor-specific fields
                if obj_type == "threat-actor":
                    if "threat_actor_types" in obj:
                        cleaned_obj["threat_actor_types"] = obj["threat_actor_types"]
                    if "sophistication" in obj:
                        cleaned_obj["sophistication"] = obj["sophistication"]

                # Vulnerability-specific fields
                if obj_type == "vulnerability":
                    if "external_references" in obj:
                        cleaned_obj["external_references"] = obj["external_references"]

                # Attack Pattern-specific fields
                if obj_type == "attack-pattern":
                    if "kill_chain_phases" in obj:
                        cleaned_obj["kill_chain_phases"] = obj["kill_chain_phases"]
                    if "x_mitre_id" in obj:
                        cleaned_obj["x_mitre_id"] = obj["x_mitre_id"]

                # Add external references if present
                if "external_references" in obj:
                    cleaned_obj["external_references"] = obj["external_references"]

                # Add object marking refs if present
                if "object_marking_refs" in obj:
                    cleaned_obj["object_marking_refs"] = obj["object_marking_refs"]

                domain_objects.append(cleaned_obj)

            except Exception as e:
                logger.warning(f"Error processing STIX object {obj_type}: {e}")

    return domain_objects


def find_main_report(objects: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Find the main report object."""
    for obj in objects:
        if isinstance(obj, dict) and obj.get("type") == "report":
            try:
                report = {
                    "id": obj.get("id", ""),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "published": obj.get("published", ""),
                    "object_refs": obj.get("object_refs", []),
                    "labels": obj.get("labels", [])
                }

                if "external_references" in obj:
                    report["external_references"] = obj["external_references"]

                return report

            except Exception as e:
                logger.warning(f"Error parsing STIX report: {e}")

    return None


def stix_parse_bundle(input_data: STIXParseInput) -> STIXParseOutput:
    """Parse STIX 2.x bundle using python-stix2 library."""
    try:
        data = input_data.json_data

        # Use python-stix2 to parse the bundle
        if isinstance(data, dict) and data.get("type") == "bundle":
            # Parse as bundle
            bundle = stix2.parse(data, allow_custom=True)
            objects = bundle.objects
        elif isinstance(data, list):
            # Parse each object individually
            objects = []
            for obj_data in data:
                try:
                    obj = stix2.parse(obj_data, allow_custom=True)
                    objects.append(obj)
                except Exception as e:
                    logger.warning(f"Failed to parse STIX object: {e}")
                    continue
        else:
            # Single object
            try:
                obj = stix2.parse(data, allow_custom=True)
                objects = [obj]
            except Exception as e:
                logger.error(f"Failed to parse single STIX object: {e}")
                # Fallback to manual parsing
                return _fallback_parse(data)

        if not objects:
            logger.warning("No objects found in STIX data")
            return STIXParseOutput(
                objects=[],
                relationships=[],
                report=None
            )

        # Convert parsed objects to dictionaries for easier processing
        parsed_objects = []
        relationships = []
        main_report = None

        for obj in objects:
            obj_dict = _stix_object_to_dict(obj)

            if obj.type == "relationship":
                relationships.append(obj_dict)
            elif obj.type == "report" and main_report is None:
                main_report = obj_dict
                parsed_objects.append(obj_dict)
            else:
                parsed_objects.append(obj_dict)

        logger.info(
            f"Parsed STIX bundle with python-stix2: {len(parsed_objects)} objects, "
            f"{len(relationships)} relationships"
        )

        return STIXParseOutput(
            objects=parsed_objects,
            relationships=relationships,
            report=main_report
        )

    except Exception as e:
        logger.error(f"Error parsing STIX bundle with python-stix2: {e}")
        # Fallback to manual parsing
        return _fallback_parse(input_data.json_data)


def _stix_object_to_dict(obj) -> Dict[str, Any]:
    """Convert STIX object to dictionary with relevant fields."""
    result = {
        "type": obj.type,
        "id": obj.id,
    }

    # Add common timestamps
    if hasattr(obj, 'created'):
        result["created"] = str(obj.created)
    if hasattr(obj, 'modified'):
        result["modified"] = str(obj.modified)

    # Add common descriptive fields
    if hasattr(obj, 'name'):
        result["name"] = obj.name
    if hasattr(obj, 'description'):
        result["description"] = obj.description
    if hasattr(obj, 'labels'):
        result["labels"] = obj.labels

    # Type-specific fields
    if obj.type == "indicator":
        if hasattr(obj, 'pattern'):
            result["pattern"] = obj.pattern
        if hasattr(obj, 'indicator_types'):
            result["indicator_types"] = obj.indicator_types

    elif obj.type == "malware":
        if hasattr(obj, 'is_family'):
            result["is_family"] = obj.is_family
        if hasattr(obj, 'malware_types'):
            result["malware_types"] = obj.malware_types

    elif obj.type == "threat-actor":
        if hasattr(obj, 'threat_actor_types'):
            result["threat_actor_types"] = obj.threat_actor_types
        if hasattr(obj, 'sophistication'):
            result["sophistication"] = obj.sophistication

    elif obj.type == "vulnerability":
        if hasattr(obj, 'external_references'):
            result["external_references"] = [ref._inner for ref in obj.external_references]

    elif obj.type == "attack-pattern":
        if hasattr(obj, 'kill_chain_phases'):
            result["kill_chain_phases"] = [phase._inner for phase in obj.kill_chain_phases]
        if hasattr(obj, 'x_mitre_id'):
            result["x_mitre_id"] = obj.x_mitre_id

    elif obj.type == "relationship":
        if hasattr(obj, 'relationship_type'):
            result["relationship_type"] = obj.relationship_type
        if hasattr(obj, 'source_ref'):
            result["source_ref"] = obj.source_ref
        if hasattr(obj, 'target_ref'):
            result["target_ref"] = obj.target_ref

    elif obj.type == "report":
        if hasattr(obj, 'published'):
            result["published"] = str(obj.published)
        if hasattr(obj, 'object_refs'):
            result["object_refs"] = obj.object_refs

    # Add external references for all objects that have them
    if hasattr(obj, 'external_references') and obj.type != "vulnerability":
        result["external_references"] = [ref._inner for ref in obj.external_references]

    # Add object marking refs
    if hasattr(obj, 'object_marking_refs'):
        result["object_marking_refs"] = obj.object_marking_refs

    return result


def _fallback_parse(data: Dict[str, Any]) -> STIXParseOutput:
    """Fallback to manual parsing when python-stix2 fails."""
    logger.info("Using fallback manual parsing for STIX data")

    # Handle different STIX structures
    if "objects" in data and isinstance(data["objects"], list):
        objects = data["objects"]
    elif isinstance(data, list):
        objects = data
    else:
        # Single object
        objects = [data]

    if not objects:
        logger.warning("No objects found in STIX data")
        return STIXParseOutput(
            objects=[],
            relationships=[],
            report=None
        )

    # Extract relationships
    relationships = extract_stix_relationships(objects)

    # Filter domain objects
    domain_objects = filter_stix_domain_objects(objects)

    # Find main report
    main_report = find_main_report(objects)

    logger.info(
        f"Parsed STIX bundle (fallback): {len(domain_objects)} objects, "
        f"{len(relationships)} relationships"
    )

    return STIXParseOutput(
        objects=domain_objects,
        relationships=relationships,
        report=main_report
    )


# Tool registration for MCP
TOOL_NAME = "stix.parse_bundle"
TOOL_DESCRIPTION = "Parse STIX 2.x bundle and extract structured data"
INPUT_SCHEMA = STIXParseInput.model_json_schema()
OUTPUT_SCHEMA = STIXParseOutput.model_json_schema()