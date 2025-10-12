"""NLP tools for CTI analysis."""
"""Fallback tool in case LLM does not work. DO NOT expect much!"""

import logging
import re
from typing import Any, Dict, List, Optional, Literal

from pydantic import BaseModel, Field


class StructuredItem(BaseModel):
    """Structured item with confidence and source."""
    value: str
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    source: str = Field(description="Source/provenance of the item")

logger = logging.getLogger(__name__)

# Type definitions
MotivationType = Literal["financial", "espionage", "hacktivism", "extortion", "sabotage", "unknown"]


class SummarizeInput(BaseModel):
    """Input for threat summarization."""

    type: str = Field(description="Content type")
    title: Optional[str] = Field(description="Content title")
    text: str = Field(description="Content text")


class SummarizeOutput(BaseModel):
    """Output for threat summarization."""

    summary: str = Field(description="Generated summary")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in summary quality")
    evidence: List[Dict[str, str]] = Field(description="Supporting evidence")


class EntitiesInput(BaseModel):
    """Input for entity extraction."""

    text: str = Field(description="Text to analyze")
    aliases: Optional[Dict[str, Any]] = Field(description="Known aliases")


class EntitiesOutput(BaseModel):
    """Output for entity extraction."""

    threat_actors: List[StructuredItem] = Field(description="Identified threat actors with confidence")
    malware: List[StructuredItem] = Field(description="Identified malware with confidence")
    victims: List[StructuredItem] = Field(description="Identified victims with confidence")
    sectors: List[StructuredItem] = Field(description="Identified sectors with confidence")
    products: List[StructuredItem] = Field(description="Identified products with confidence")
    evidence: List[Dict[str, str]] = Field(description="Supporting evidence")
    token_usage: Optional[Dict[str, int]] = Field(default=None, description="LLM token usage")


class GeoInput(BaseModel):
    """Input for geographic scope classification."""

    text: str = Field(description="Text to analyze")


class GeoOutput(BaseModel):
    """Output for geographic scope classification."""

    affects_singapore: bool = Field(description="Affects Singapore")
    affects_asean: bool = Field(description="Affects ASEAN region")
    singapore_confidence: float = Field(ge=0.0, le=1.0, description="Confidence for Singapore impact")
    asean_confidence: float = Field(ge=0.0, le=1.0, description="Confidence for ASEAN impact")
    evidence: List[Dict[str, str]] = Field(description="Supporting evidence")


class TensionInput(BaseModel):
    """Input for high tension event classification."""

    text: str = Field(description="Text to analyze")


class TensionOutput(BaseModel):
    """Output for high tension event classification."""

    high_tension_event: bool = Field(description="Is high tension event")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    event_description: str = Field(description="Description of the tension event")
    evidence: List[Dict[str, str]] = Field(description="Supporting evidence")


class MotivationInput(BaseModel):
    """Input for motivation classification."""

    text: str = Field(description="Text to analyze")


class MotivationOutput(BaseModel):
    """Output for motivation classification."""

    motivations: List[StructuredItem] = Field(description="Identified motivations with confidence")
    evidence: List[Dict[str, str]] = Field(description="Supporting evidence")


class CyberInput(BaseModel):
    """Input for cyber-relatedness classification."""

    text: str = Field(description="Text to analyze")


class CyberOutput(BaseModel):
    """Output for cyber-relatedness classification."""

    cyber_related: bool = Field(description="Is cyber-related")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")


def extract_evidence_snippets(text: str, patterns: List[str], max_snippets: int = 3) -> List[Dict[str, str]]:
    """Extract evidence snippets from text based on patterns."""
    evidence = []
    text_lower = text.lower()

    for pattern in patterns:
        matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
        for match in matches[:max_snippets]:
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            snippet = text[start:end].strip()

            # Clean up snippet
            snippet = re.sub(r'\s+', ' ', snippet)
            if len(snippet) > 240:
                snippet = snippet[:240] + "..."

            evidence.append({
                "loc": "body",
                "text": snippet
            })

            if len(evidence) >= max_snippets:
                break

    return evidence


def summarize_threat(input_data: SummarizeInput) -> SummarizeOutput:
    """Generate threat intelligence summary using SummarizeAgent."""
    try:
        from ..orchestrator.agents.summarize_agent import SummarizeAgent
        from ..state import GraphState

        # Create a temporary state with the input text
        state = GraphState(url="", raw_content=input_data.text)
        state.parsed = {"text": input_data.text, "title": input_data.title}

        # Use SummarizeAgent to process the content
        agent = SummarizeAgent()
        processed_state = agent.process(state)

        # Return the summary from the processed state
        summary = processed_state.extracted.get("summary", "No summary generated")

        return SummarizeOutput(
            summary=summary,
            confidence=0.85,  # High confidence for LLM-based summary
            evidence=[{"type": "llm_generated", "text": summary[:200]}]
        )

    except Exception as e:
        logger.error(f"Error in SummarizeAgent: {e}")
        # Fallback to basic summary
        text = input_data.text[:500] + "..." if len(input_data.text) > 500 else input_data.text
        return SummarizeOutput(
            summary=f"Summary of {input_data.type} content: {text}",
            confidence=0.3,
            evidence=[{"type": "fallback", "text": "Agent failed, using basic summary"}]
        )


def extract_entities(input_data: EntitiesInput) -> EntitiesOutput:
    """Extract threat intelligence entities using EntityAgent through MCP interface."""
    try:
        # Import here to avoid circular imports
        from ..orchestrator.agents.entity_agent import EntityAgent
        from ..state import GraphState

        logger.info("Using EntityAgent for sophisticated entity extraction")

        # Create a mock state with parsed text content
        state = GraphState(url="mcp://extract_entities")
        state.parsed = {"text": input_data.text}

        # Use the EntityAgent for sophisticated entity extraction
        agent = EntityAgent()
        result_state = agent.process(state)

        # Convert agent results to structured objects
        def convert_to_structured(items, source_type):
            return [StructuredItem(
                value=item,
                confidence=0.85,  # High confidence for LLM extraction
                source=f"llm_{source_type}_extraction"
            ) for item in items] if items else []

        # Extract results from state
        threat_actors = convert_to_structured(result_state.extracted.get("threat_actors", []), "threat_actor")
        malware = convert_to_structured(result_state.extracted.get("malware", []), "malware")
        victims = convert_to_structured(result_state.extracted.get("victims", []), "victim")
        sectors = convert_to_structured(result_state.extracted.get("sectors", []), "sector")
        products = convert_to_structured(result_state.extracted.get("affected_products", []), "product")

        # Convert evidence
        evidence = []
        for ev in result_state.evidence:
            if ev.get("text"):
                evidence.append({
                    "loc": ev.get("loc", "body"),
                    "text": ev["text"]
                })

        logger.info(f"EntityAgent extraction: {len(threat_actors)} actors, {len(malware)} malware, "
                   f"{len(victims)} victims, {len(sectors)} sectors, {len(products)} products")

        return EntitiesOutput(
            threat_actors=threat_actors,
            malware=malware,
            victims=victims,
            sectors=sectors,
            products=products,
            evidence=evidence
        )

    except Exception as e:
        logger.error(f"Error in EntityAgent extraction: {e}")
        # Fallback to empty results
        return EntitiesOutput(
            threat_actors=[],
            malware=[],
            victims=[],
            sectors=[],
            products=[],
            evidence=[]
        )


def classify_geo_scope(input_data: GeoInput) -> GeoOutput:
    """Classify geographic scope of threat using GeoMotivationAgent."""
    try:
        from ..orchestrator.agents.geo_motivation_agent import GeoMotivationAgent
        from ..state import GraphState

        # Create a temporary state with the input text
        state = GraphState(url="", raw_content=input_data.text)
        state.parsed = {"text": input_data.text}

        # Use GeoMotivationAgent to process the content
        agent = GeoMotivationAgent()
        processed_state = agent.process(state)

        # Return the geographic analysis from the processed state
        affects_singapore = processed_state.extracted.get("affects_singapore", False)
        affects_asean = processed_state.extracted.get("affects_asean", False)

        return GeoOutput(
            affects_singapore=affects_singapore,
            affects_asean=affects_asean,
            singapore_confidence=0.85 if affects_singapore else 0.15,
            asean_confidence=0.85 if affects_asean else 0.15,
            evidence=[{"type": "llm_analysis", "text": input_data.text[:200]}]
        )

    except Exception as e:
        logger.error(f"Error in geo classification: {e}")
        return GeoOutput(
            affects_singapore=False,
            affects_asean=False,
            singapore_confidence=0.15,
            asean_confidence=0.15,
            evidence=[]
        )


def classify_high_tension(input_data: TensionInput) -> TensionOutput:
    """Classify if this is a high tension event."""
    try:
        text = input_data.text.lower()

        # High tension indicators
        tension_patterns = [
            r'\b(?:national\s+security|critical\s+infrastructure|government|military|defense)\b',
            r'\b(?:widespread|massive|significant|critical|severe|major)\s+(?:attack|breach|incident)\b',
            r'\b(?:state\s+sponsored|nation\s+state|apt|advanced\s+persistent)\b',
            r'\b(?:cyber\s+warfare|cyber\s+attack|cyber\s+operation)\b',
            r'\b(?:espionage|intelligence|surveillance)\b',
            r'\b(?:election|voting|democracy|political)\b.*(?:attack|interference|manipulation)\b'
        ]

        high_tension = any(re.search(pattern, text) for pattern in tension_patterns)

        evidence = []
        if high_tension:
            evidence.extend(extract_evidence_snippets(text, tension_patterns, 3))

        logger.info(f"High tension classification: {high_tension}")

        return TensionOutput(
            high_tension_event=high_tension,
            evidence=evidence
        )

    except Exception as e:
        logger.error(f"Error in tension classification: {e}")
        return TensionOutput(
            high_tension_event=False,
            evidence=[]
        )


def classify_motivation(input_data: MotivationInput) -> MotivationOutput:
    """Classify threat actor motivation."""
    try:
        text = input_data.text.lower()
        motivations = []

        # Motivation patterns
        motivation_patterns = {
            "financial": [
                r'\b(?:money|profit|financial|ransom|extortion|cryptocurrency|bitcoin|payment)\b',
                r'\b(?:banking|financial|credit\s+card|payment\s+system)\b.*(?:attack|breach|fraud)\b'
            ],
            "espionage": [
                r'\b(?:espionage|intelligence|surveillance|reconnaissance|data\s+theft)\b',
                r'\b(?:steal|exfiltrate|collect).*(?:information|data|secrets|documents)\b',
                r'\b(?:state\s+sponsored|nation\s+state|government|military)\b.*(?:actor|group)\b'
            ],
            "hacktivism": [
                r'\b(?:hacktivist|hacktivism|activist|protest|political)\b',
                r'\b(?:anonymous|defacement|website\s+defacement)\b',
                r'\b(?:political|ideological|social)\s+(?:motivation|cause|agenda)\b'
            ],
            "extortion": [
                r'\b(?:extortion|blackmail|ransom|ransomware)\b',
                r'\b(?:pay|payment|bitcoin|cryptocurrency).*(?:decrypt|unlock|restore)\b'
            ],
            "sabotage": [
                r'\b(?:sabotage|disruption|destruction|damage)\b',
                r'\b(?:industrial|infrastructure|utility|power|energy)\b.*(?:attack|disruption)\b',
                r'\b(?:scada|ics|industrial\s+control)\b'
            ]
        }

        for motivation, patterns in motivation_patterns.items():
            if any(re.search(pattern, text) for pattern in patterns):
                motivations.append(motivation)  # type: ignore

        # Default to unknown if no clear motivation
        if not motivations:
            motivations = ["unknown"]

        # Extract evidence
        evidence = []
        for motivation in motivations:
            if motivation in motivation_patterns:
                evidence.extend(extract_evidence_snippets(text, motivation_patterns[motivation], 1))

        logger.info(f"Classified motivations: {motivations}")

        return MotivationOutput(
            motivations=motivations,  # type: ignore
            evidence=evidence[:5]
        )

    except Exception as e:
        logger.error(f"Error in motivation classification: {e}")
        return MotivationOutput(
            motivations=["unknown"],
            evidence=[]
        )


def is_cyber_related(input_data: CyberInput) -> CyberOutput:
    """Determine if content is cyber security related using CyberAgent."""
    try:
        from ..orchestrator.agents.cyber_agent import CyberAgent
        from ..state import GraphState

        # Create a temporary state with the input text
        state = GraphState(url="", raw_content=input_data.text)
        state.parsed = {"text": input_data.text}

        # Use CyberAgent to process the content
        agent = CyberAgent()
        processed_state = agent.process(state)

        # Return the cyber-relatedness analysis from the processed state
        is_cyber = processed_state.extracted.get("cyber_related", False)

        return CyberOutput(
            is_cyber_related=is_cyber,
            confidence=0.85 if is_cyber else 0.15,
            evidence=[{"type": "llm_analysis", "text": input_data.text[:200]}]
        )

    except Exception as e:
        logger.error(f"Error in cyber classification: {e}")
        return CyberOutput(
            is_cyber_related=True,  # Default to True on error
            confidence=0.3,
            evidence=[{"type": "fallback", "text": "Agent failed, defaulting to cyber-related"}]
        )


# Tool registrations for MCP
SUMMARIZE_TOOL = {
    "name": "nlp.summarize_threat",
    "description": "Generate threat intelligence summary from text",
    "input_schema": SummarizeInput.model_json_schema(),
    "output_schema": SummarizeOutput.model_json_schema()
}

ENTITIES_TOOL = {
    "name": "nlp.extract_entities",
    "description": "Extract threat intelligence entities from text",
    "input_schema": EntitiesInput.model_json_schema(),
    "output_schema": EntitiesOutput.model_json_schema()
}

GEO_TOOL = {
    "name": "nlp.classify_geo_scope",
    "description": "Classify geographic scope of threat",
    "input_schema": GeoInput.model_json_schema(),
    "output_schema": GeoOutput.model_json_schema()
}

TENSION_TOOL = {
    "name": "nlp.classify_high_tension",
    "description": "Classify if event is high tension",
    "input_schema": TensionInput.model_json_schema(),
    "output_schema": TensionOutput.model_json_schema()
}

MOTIVATION_TOOL = {
    "name": "nlp.classify_motivation",
    "description": "Classify threat actor motivation",
    "input_schema": MotivationInput.model_json_schema(),
    "output_schema": MotivationOutput.model_json_schema()
}

CYBER_TOOL = {
    "name": "nlp.is_cyber_related",
    "description": "Determine if content is cyber security related",
    "input_schema": CyberInput.model_json_schema(),
    "output_schema": CyberOutput.model_json_schema()
}