"""Schema validation and healing tool."""

import logging
from typing import Any, Dict, List

import jsonschema
from pydantic import BaseModel, Field

from ..state import CTIArtifact

logger = logging.getLogger(__name__)


class SchemaInput(BaseModel):
    """Input for schema validation and healing."""

    json_data: Dict[str, Any] = Field(description="JSON object to validate", alias="json")
    schema_data: Dict[str, Any] = Field(description="JSON schema to validate against", alias="schema")


class SchemaOutput(BaseModel):
    """Output for schema validation and healing."""

    ok: bool = Field(description="Whether validation passed")
    errors: List[Dict[str, Any]] = Field(description="Validation errors")
    healed: Dict[str, Any] = Field(description="Healed/fixed JSON object")


def get_cti_artifact_schema() -> Dict[str, Any]:
    """Get the CTI artifact JSON schema."""
    return CTIArtifact.model_json_schema()


def heal_missing_fields(data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """Heal missing required fields with default values."""
    healed = data.copy()

    # Get properties from schema
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    for field_name, field_schema in properties.items():
        field_type = field_schema.get("type")

        if field_name not in healed:
            # Add missing field with default value
            if field_type == "string":
                healed[field_name] = ""
            elif field_type == "array":
                healed[field_name] = []
            elif field_type == "object":
                if field_name == "iocs":
                    healed[field_name] = {
                        "urls": [],
                        "domains": [],
                        "hashes": [],
                        "ips": []
                    }
                elif field_name == "cve_severity":
                    healed[field_name] = {}
                else:
                    healed[field_name] = {}
            elif field_type == "boolean":
                healed[field_name] = False
            elif field_type == "integer":
                healed[field_name] = 0
            elif field_type == "number":
                healed[field_name] = 0.0
            else:
                # Handle null types
                if "null" in str(field_schema.get("anyOf", [])):
                    healed[field_name] = None
                else:
                    healed[field_name] = None

        elif healed[field_name] is None and field_name in required:
            # Fix null values for required fields
            if field_type == "string":
                healed[field_name] = ""
            elif field_type == "array":
                healed[field_name] = []
            elif field_type == "object":
                if field_name == "iocs":
                    healed[field_name] = {
                        "urls": [],
                        "domains": [],
                        "hashes": [],
                        "ips": []
                    }
                elif field_name == "cve_severity":
                    healed[field_name] = {}
                else:
                    healed[field_name] = {}
            elif field_type == "boolean":
                healed[field_name] = False

    # Special handling for iocs field structure
    if "iocs" in healed and isinstance(healed["iocs"], dict):
        ioc_defaults = {"urls": [], "domains": [], "hashes": [], "ips": []}
        for ioc_type in ioc_defaults:
            if ioc_type not in healed["iocs"]:
                healed["iocs"][ioc_type] = []
            elif healed["iocs"][ioc_type] is None:
                healed["iocs"][ioc_type] = []

    return healed


def fix_type_errors(data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """Fix type mismatches in the data."""
    healed = data.copy()
    properties = schema.get("properties", {})

    for field_name, field_schema in properties.items():
        if field_name not in healed:
            continue

        value = healed[field_name]
        expected_type = field_schema.get("type")

        try:
            if expected_type == "string" and not isinstance(value, str):
                if value is None:
                    healed[field_name] = ""
                else:
                    healed[field_name] = str(value)

            elif expected_type == "array" and not isinstance(value, list):
                if value is None:
                    healed[field_name] = []
                elif isinstance(value, str):
                    # Try to split string into array
                    healed[field_name] = [item.strip() for item in value.split(",") if item.strip()]
                else:
                    healed[field_name] = [value]

            elif expected_type == "object" and not isinstance(value, dict):
                if value is None:
                    if field_name == "iocs":
                        healed[field_name] = {"urls": [], "domains": [], "hashes": [], "ips": []}
                    elif field_name == "cve_severity":
                        healed[field_name] = {}
                    else:
                        healed[field_name] = {}
                else:
                    healed[field_name] = {}

            elif expected_type == "boolean" and not isinstance(value, bool):
                if value is None:
                    healed[field_name] = False
                elif isinstance(value, str):
                    healed[field_name] = value.lower() in ("true", "yes", "1", "on")
                elif isinstance(value, (int, float)):
                    healed[field_name] = bool(value)
                else:
                    healed[field_name] = bool(value)

        except Exception as e:
            logger.warning(f"Error fixing type for field {field_name}: {e}")

    return healed


def clean_array_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """Clean array fields by removing null/empty values and ensuring uniqueness."""
    healed = data.copy()

    array_fields = [
        "threat_actors", "malware", "cve_vulns", "affected_products",
        "mitre_ttps",
        "victims", "sectors", "possible_motivations",
        "recommendations_and_mitigations"
    ]

    for field in array_fields:
        if field in healed and isinstance(healed[field], list):
            # Remove null/empty values and deduplicate
            cleaned = []
            seen = set()

            for item in healed[field]:
                if item and isinstance(item, str) and item.strip():
                    clean_item = item.strip()
                    if clean_item not in seen:
                        seen.add(clean_item)
                        cleaned.append(clean_item)

            healed[field] = cleaned

    # Special handling for IOCs
    if "iocs" in healed and isinstance(healed["iocs"], dict):
        for ioc_type in ["urls", "domains", "hashes", "ips"]:
            if ioc_type in healed["iocs"] and isinstance(healed["iocs"][ioc_type], list):
                cleaned = []
                seen = set()

                for item in healed["iocs"][ioc_type]:
                    if item and isinstance(item, str) and item.strip():
                        clean_item = item.strip()
                        if clean_item not in seen:
                            seen.add(clean_item)
                            cleaned.append(clean_item)

                healed["iocs"][ioc_type] = cleaned

    return healed


def validate_and_heal(input_data: SchemaInput) -> SchemaOutput:
    """Validate JSON against schema and heal common issues."""
    try:
        data = input_data.json_data
        schema = input_data.schema_data

        # If no schema provided, use CTI artifact schema
        if not schema:
            schema = get_cti_artifact_schema()

        # First validation attempt
        errors = []
        try:
            jsonschema.validate(data, schema)
            # Validation passed
            return SchemaOutput(
                ok=True,
                errors=[],
                healed=data
            )
        except jsonschema.ValidationError as e:
            errors.append({
                "path": list(e.absolute_path),
                "message": e.message,
                "schema_path": list(e.schema_path)
            })
        except jsonschema.SchemaError as e:
            errors.append({
                "path": [],
                "message": f"Schema error: {e.message}",
                "schema_path": []
            })

        # Attempt to heal the data
        healed = data.copy()

        # Step 1: Add missing fields with defaults
        healed = heal_missing_fields(healed, schema)

        # Step 2: Fix type mismatches
        healed = fix_type_errors(healed, schema)

        # Step 3: Clean array fields
        healed = clean_array_fields(healed)

        # Second validation attempt on healed data
        healed_errors = []
        validation_ok = False

        try:
            jsonschema.validate(healed, schema)
            validation_ok = True
            logger.info("Schema validation passed after healing")
        except jsonschema.ValidationError as e:
            healed_errors.append({
                "path": list(e.absolute_path),
                "message": e.message,
                "schema_path": list(e.schema_path)
            })
        except jsonschema.SchemaError as e:
            healed_errors.append({
                "path": [],
                "message": f"Schema error: {e.message}",
                "schema_path": []
            })

        # Return results
        final_errors = healed_errors if healed_errors else errors

        logger.info(
            f"Schema validation: ok={validation_ok}, "
            f"original_errors={len(errors)}, healed_errors={len(healed_errors)}"
        )

        return SchemaOutput(
            ok=validation_ok,
            errors=final_errors,
            healed=healed
        )

    except Exception as e:
        logger.error(f"Error in schema validation: {e}")
        return SchemaOutput(
            ok=False,
            errors=[{"path": [], "message": f"Validation error: {str(e)}", "schema_path": []}],
            healed=input_data.json_data
        )


# Tool registration for MCP
TOOL_NAME = "schema.validate_and_heal"
TOOL_DESCRIPTION = "Validate JSON against schema and heal common issues"
INPUT_SCHEMA = SchemaInput.model_json_schema()
OUTPUT_SCHEMA = SchemaOutput.model_json_schema()