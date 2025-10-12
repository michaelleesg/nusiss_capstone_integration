"""LangGraph state models."""

from typing import Dict, List, Literal, Optional, Any, Annotated
from pydantic import BaseModel, Field


def merge_extracted(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Custom merge function for extracted data."""
    if not left and not right:
        return {}
    if not left:
        return right
    if not right:
        return left

    # Simple merge - right takes precedence
    result = left.copy()
    result.update(right)
    return result


def merge_simple(left: Any, right: Any) -> Any:
    """Simple merge: right takes precedence."""
    return right if right is not None else left


def merge_token_usage(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Custom merge function for token usage - accumulates totals."""
    if not left and not right:
        return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "agents": {}, "processing_time": 0.0}
    if not left:
        return right
    if not right:
        return left

    # Merge token usage by accumulating totals and preserving agent-specific data
    result = {
        "input_tokens": left.get("input_tokens", 0) + right.get("input_tokens", 0),
        "output_tokens": left.get("output_tokens", 0) + right.get("output_tokens", 0),
        "total_tokens": left.get("total_tokens", 0) + right.get("total_tokens", 0),
        "processing_time": left.get("processing_time", 0.0) + right.get("processing_time", 0.0),
        "agents": {}
    }

    # Merge agent-specific data
    all_agents = set(left.get("agents", {}).keys()) | set(right.get("agents", {}).keys())
    for agent in all_agents:
        left_agent = left.get("agents", {}).get(agent, {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "processing_time": 0.0, "calls": 0})
        right_agent = right.get("agents", {}).get(agent, {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "processing_time": 0.0, "calls": 0})
        result["agents"][agent] = {
            "input_tokens": left_agent.get("input_tokens", 0) + right_agent.get("input_tokens", 0),
            "output_tokens": left_agent.get("output_tokens", 0) + right_agent.get("output_tokens", 0),
            "total_tokens": left_agent.get("total_tokens", 0) + right_agent.get("total_tokens", 0),
            "processing_time": left_agent.get("processing_time", 0.0) + right_agent.get("processing_time", 0.0),
            "calls": left_agent.get("calls", 0) + right_agent.get("calls", 0)
        }

    return result


class GraphState(BaseModel):
    """State passed between LangGraph nodes."""

    # URL should never change after initialization but annotate for safety
    url: Annotated[str, merge_simple]
    # Authentication credentials for HTTP basic auth
    auth_username: Annotated[Optional[str], merge_simple] = None
    auth_password: Annotated[Optional[str], merge_simple] = None
    # SSL verification control
    verify_ssl: Annotated[bool, merge_simple] = True
    fetched: Annotated[Optional[Dict[str, Any]], merge_simple] = None  # {status, headers, mime, content_b64, sha256}
    detected_type: Annotated[Optional[Literal["MISP", "STIX", "RSS", "HTML", "PDF", "JSON", "TEXT"]], merge_simple] = None
    llm_parser_selection: Annotated[Optional[Dict[str, Any]], merge_simple] = None  # LLM-based parser choice
    parsed: Annotated[Optional[Dict[str, Any]], merge_simple] = None  # type-specific parsed data
    markdown: Annotated[Optional[str], merge_simple] = None
    extracted: Annotated[Dict[str, Any], merge_extracted] = Field(default_factory=lambda: {
        "title": "",
        "source_url": "",
        "summary": "",
        "threat_actors": [],
        "malware": [],
        "cve_vulns": [],
        "affected_products": [],
        "iocs": {
            "urls": [],
            "domains": [],
            "ips": [],
            "hashes": [],
            "commands": [],
            "file_paths": [],
            "processes": [],
            "registry_keys": [],
            "email_addresses": []
        },
        "mitre_ttps": [],
        "victims": [],
        "sectors": [],
        "patch_availability": "",
        "affects_singapore": False,
        "affects_asean": False,
        "active_exploitation": False,
        "high_tension_event": "",
        "possible_motivations": [],
        "recommendations_and_mitigations": "",
        "cve_severity": [],
        "underlying_causes": [],
        "strategic_implications": [],
        "regional_context": "",
        "escalation_potential": "",
        "stakeholder_interests": "",
        "markdown": ""
    })
    evidence: Annotated[List[Dict[str, Any]], lambda x, y: x + y] = Field(default_factory=list)  # {kind, locator, text?}
    # Agentic AI fields
    next_action: Annotated[Optional[str], merge_simple] = None  # Next action decided by orchestrator
    decision_reasoning: Annotated[Optional[str], merge_simple] = None  # Reasoning for decision
    # RSS feed processing results - list of independent CTI analyses for each RSS item
    rss_results: Annotated[List[Dict[str, Any]], lambda x, y: x + y] = Field(default_factory=list)
    # Token usage tracking
    token_usage: Annotated[Dict[str, Any], merge_token_usage] = Field(default_factory=lambda: {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "processing_time": 0.0,
        "agents": {}
    })


class StructuredItem(BaseModel):
    """Structured item with confidence and source."""
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str


class CTIArtifact(BaseModel):
    """Final CTI artifact output schema matching requirements."""

    title: str
    url: str
    source_url: str
    summary: str
    threat_actors: List[str]
    malware: List[str]
    cve_vulns: List[str]
    affected_products: List[str]
    iocs: Dict[str, List[str]] = Field(default_factory=lambda: {
        "urls": [],     # URLs
        "domains": [],  # Domain names
        "ips": [],      # IP addresses
        "hashes": [],   # File hashes
        "commands": [], # Commands
        "file_paths": [], # File paths
        "processes": [], # Process names
        "registry_keys": [], # Registry keys
        "email_addresses": [] # Email addresses
    })
    mitre_ttps: List[str]
    victims: List[str]
    sectors: List[str]
    patch_availability: str
    affects_singapore: bool
    affects_asean: bool
    active_exploitation: bool
    high_tension_event: str
    possible_motivations: List[str]
    recommendations_and_mitigations: str
    cve_severity: List[str]
    underlying_causes: List[str]
    strategic_implications: List[str]
    regional_context: str
    escalation_potential: str
    stakeholder_interests: str
    markdown: str


class Evidence(BaseModel):
    """Evidence supporting extracted information."""

    kind: str  # e.g., "entity", "ioc", "cve", "ttp"
    locator: str  # e.g., "title", "body"
    text: Optional[str] = None  # Supporting text snippet