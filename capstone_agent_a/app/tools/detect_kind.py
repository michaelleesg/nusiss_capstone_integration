"""Content type detection tool."""

import json
import logging
import re
from typing import Literal

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Try to import stix2-validator for definitive STIX validation
try:
    from stix2validator import validate_string as stix_validate_string
    STIX_VALIDATOR_AVAILABLE = True
except ImportError:
    STIX_VALIDATOR_AVAILABLE = False
    logger.warning("stix2-validator not available, falling back to heuristic STIX detection")

ContentType = Literal["MISP", "STIX", "RSS", "HTML", "PDF", "JSON", "TEXT"]


class DetectInput(BaseModel):
    """Input for content type detection."""

    mime: str = Field(description="MIME type from HTTP headers")
    sample_text: str = Field(description="Sample text from content (first 2KB)")


class DetectOutput(BaseModel):
    """Output for content type detection."""

    detected_type: ContentType = Field(description="Detected content type")
    confidence: float = Field(description="Confidence score 0.0-1.0")


def detect_stix_content(text: str) -> float:
    """Detect STIX 2.x content using stix2-validator if available, fallback to heuristics."""
    try:
        # First, try stix2-validator for definitive validation
        if STIX_VALIDATOR_AVAILABLE:
            try:
                # Only attempt validation if it looks like JSON
                text_stripped = text.strip()
                if text_stripped.startswith('{') or text_stripped.startswith('['):
                    validation_result = stix_validate_string(text)
                    if validation_result.is_valid:
                        logger.debug("stix2-validator confirmed valid STIX content")
                        return 1.0
                    elif len(validation_result.errors) == 0:
                        # No errors but not fully valid - might be partial STIX
                        logger.debug("stix2-validator found no errors but not fully valid")
                        return 0.8
                    else:
                        # Has validation errors - check if it's due to minor issues
                        error_count = len(validation_result.errors)
                        if error_count <= 2:
                            logger.debug(f"stix2-validator found {error_count} minor errors")
                            return 0.6
                        else:
                            logger.debug(f"stix2-validator found {error_count} errors, trying heuristics")
                            # Fall through to heuristic detection
            except Exception as e:
                logger.debug(f"stix2-validator failed: {e}, falling back to heuristics")
                # Fall through to heuristic detection

        # Fallback heuristic detection
        # Look for STIX indicators in text
        stix_patterns = [
            r'"type"\s*:\s*"bundle"',
            r'"spec_version"\s*:\s*"2\.[01]"',
            r'"type"\s*:\s*"indicator"',
            r'"type"\s*:\s*"malware"',
            r'"type"\s*:\s*"threat-actor"',
            r'"type"\s*:\s*"attack-pattern"',
            r'"pattern"\s*:\s*"\[.*\]"',  # STIX patterns
            r'"labels"\s*:\s*\[.*"malicious-activity"',
        ]

        score = 0.0
        for pattern in stix_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.15

        # Try parsing as JSON and look for STIX structure
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                # STIX bundle detection
                if data.get("type") == "bundle":
                    score += 0.4
                    # Check for spec_version in bundle or objects
                    if "spec_version" in data:
                        score += 0.2

                if "objects" in data and isinstance(data["objects"], list):
                    score += 0.2
                    stix_objects_found = 0
                    has_spec_version = False

                    # Check for STIX object types and spec_version
                    for obj in data["objects"][:10]:  # Check first 10 objects
                        if isinstance(obj, dict):
                            obj_type = obj.get("type")
                            if obj_type in [
                                "indicator", "malware", "threat-actor", "attack-pattern",
                                "vulnerability", "tool", "campaign", "intrusion-set",
                                "relationship", "report", "malware-analysis"
                            ]:
                                score += 0.05
                                stix_objects_found += 1

                            # Check for spec_version in objects (STIX 2.1 pattern)
                            if "spec_version" in obj and obj["spec_version"].startswith("2."):
                                has_spec_version = True

                    # Boost score if we found STIX objects with spec_version
                    if stix_objects_found > 0 and has_spec_version:
                        score += 0.3
        except json.JSONDecodeError:
            pass

        return min(score, 1.0)

    except Exception:
        return 0.0


def detect_misp_content(text: str) -> float:
    """Detect MISP content."""
    try:
        misp_patterns = [
            r'"Event"\s*:\s*{',
            r'"Attribute"\s*:\s*\[',
            r'"orgc_id"\s*:',
            r'"sharing_group_id"\s*:',
            r'"published"\s*:\s*(true|false)',
            r'"threat_level_id"\s*:',
            r'"analysis"\s*:\s*"[012]"',
            r'"category"\s*:\s*"(Network activity|Payload|Artifacts|Attribution)"',
        ]

        score = 0.0
        for pattern in misp_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.15

        # Try parsing as JSON and look for MISP structure
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                if "Event" in data:
                    score += 0.3
                    event = data["Event"]
                    if isinstance(event, dict):
                        if "Attribute" in event:
                            score += 0.2
                        if "orgc_id" in event or "sharing_group_id" in event:
                            score += 0.2
                        if "threat_level_id" in event:
                            score += 0.1

                # Check for MISP attribute structure
                if "Attribute" in data and isinstance(data["Attribute"], list):
                    score += 0.3

        except json.JSONDecodeError:
            pass

        return min(score, 1.0)

    except Exception:
        return 0.0


def detect_rss_content(text: str) -> float:
    """Detect RSS/Atom feed content."""
    try:
        rss_patterns = [
            r'<rss\s+version=',
            r'<feed\s+xmlns=',
            r'<channel>',
            r'<item>',
            r'<entry>',
            r'<title>.*</title>',
            r'<description>',
            r'<pubDate>',
            r'<lastBuildDate>',
        ]

        score = 0.0
        for pattern in rss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.15

        return min(score, 1.0)

    except Exception:
        return 0.0


def detect_html_content(text: str, mime: str) -> float:
    """Detect HTML content."""
    try:
        if "html" in mime.lower():
            return 0.7

        html_patterns = [
            r'<!DOCTYPE\s+html',
            r'<html[^>]*>',
            r'<head>',
            r'<body>',
            r'<title>.*</title>',
            r'<meta\s+[^>]*>',
            r'<div[^>]*>',
            r'<p[^>]*>',
        ]

        score = 0.0
        for pattern in html_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.1

        return min(score, 1.0)

    except Exception:
        return 0.0


def detect_pdf_content(mime: str, sample: str) -> float:
    """Detect PDF content."""
    if "pdf" in mime.lower():
        return 0.9

    if sample.startswith("%PDF"):
        return 0.9

    return 0.0


def detect_json_content(text: str, mime: str) -> float:
    """Detect generic JSON content."""
    try:
        if "json" in mime.lower():
            base_score = 0.5
        else:
            base_score = 0.0

        # Try parsing as JSON
        try:
            data = json.loads(text)
            if isinstance(data, (dict, list)):
                base_score += 0.3

                # Deduct score if it looks like STIX or MISP
                if detect_stix_content(text) > 0.3:
                    base_score -= 0.4
                elif detect_misp_content(text) > 0.3:
                    base_score -= 0.4

        except json.JSONDecodeError:
            pass

        return max(min(base_score, 1.0), 0.0)

    except Exception:
        return 0.0


def detect_kind(input_data: DetectInput) -> DetectOutput:
    """Detect content type with confidence scoring."""
    try:
        mime = input_data.mime.lower()
        sample = input_data.sample_text[:2048]  # Use first 2KB for most detectors

        # For STIX detection, use the complete content for accurate validation
        full_content = input_data.sample_text

        scores = {
            "STIX": detect_stix_content(full_content),
            "MISP": detect_misp_content(sample),
            "RSS": detect_rss_content(sample),
            "HTML": detect_html_content(sample, mime),
            "PDF": detect_pdf_content(mime, sample),
            "JSON": detect_json_content(sample, mime),
            "TEXT": 0.1  # Fallback baseline
        }

        # Boost scores based on MIME type
        if "json" in mime:
            scores["JSON"] += 0.2
            scores["STIX"] += 0.1
            scores["MISP"] += 0.1
        elif "xml" in mime or "rss" in mime or "atom" in mime:
            scores["RSS"] += 0.3
        elif "html" in mime:
            scores["HTML"] += 0.3
        elif "pdf" in mime:
            scores["PDF"] += 0.5
        elif "text" in mime:
            scores["TEXT"] += 0.2

        # Special handling: RSS content should override HTML even with HTML MIME type
        # This handles cases where RSS feeds are served with text/html MIME type
        if scores["RSS"] > 0.3 and scores["HTML"] > scores["RSS"] and "html" in mime:
            logger.info(f"RSS content detected (score: {scores['RSS']:.2f}) but HTML MIME type present - overriding to RSS")
            best_type = "RSS"
            confidence = scores["RSS"]
        else:
            # Find best match
            best_type = max(scores.keys(), key=lambda k: scores[k])
            confidence = scores[best_type]

        # Ensure minimum confidence for fallback
        if confidence < 0.2:
            best_type = "TEXT"
            confidence = 0.2

        logger.info(f"Detected content type: {best_type} (confidence: {confidence:.2f})")
        logger.debug(f"All scores: {scores}")

        return DetectOutput(
            detected_type=best_type,  # type: ignore
            confidence=confidence
        )

    except Exception as e:
        logger.error(f"Error in content detection: {e}")
        return DetectOutput(
            detected_type="TEXT",
            confidence=0.1
        )


# Tool registration for MCP
TOOL_NAME = "detect.kind"
TOOL_DESCRIPTION = "Detect content type from MIME and sample text"
INPUT_SCHEMA = DetectInput.model_json_schema()
OUTPUT_SCHEMA = DetectOutput.model_json_schema()