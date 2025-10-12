"""Content type detection agent."""

import base64

from .base_agent import BaseAgent
from ...state import GraphState
from ...tool_proxy import call_tool


class DetectTypeAgent(BaseAgent):
    """Agent responsible for detecting content type."""

    def __init__(self):
        super().__init__("detect_type")

    def get_system_prompt(self) -> str:
        """Get system prompt for content type detection."""
        return """You are a content type detection agent for Cyber Threat Intelligence (CTI) analysis.

Your responsibility is to analyze MIME types and content samples to determine the best parsing approach.

Content Types:
- MISP: MISP event JSON with Event structure
- STIX: STIX 2.x bundle with spec_version and objects
- RSS: RSS/Atom feed XML
- HTML: Web pages and reports
- PDF: PDF documents
- JSON: Generic JSON data
- TEXT: Plain text fallback

Be conservative - prefer TEXT for ambiguous content."""

    def process(self, state: GraphState) -> GraphState:
        """Detect content type from fetched data."""
        try:
            if not state.fetched:
                raise ValueError("No fetched content available")

            # Decode full content for detection (STIX validation needs complete content)
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            full_text = content_bytes.decode('utf-8', errors='ignore')

            # Detect content type using tool proxy
            detect_result = call_tool("detect_kind",
                mime=state.fetched["mime"],
                sample_text=full_text
            )

            state.detected_type = detect_result["detected_type"]

            self.log_processing("Content type detected", {
                "type": detect_result["detected_type"],
                "confidence": detect_result["confidence"],
                "mime": state.fetched["mime"]
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in type detection: {e}")
            state.detected_type = "TEXT"
            return state