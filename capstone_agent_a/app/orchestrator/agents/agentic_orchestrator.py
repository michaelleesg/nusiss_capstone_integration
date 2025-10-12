"""Truly agentic orchestrator that dynamically discovers MCP tools and makes intelligent decisions."""

import json
import logging
from typing import Dict, Any, List, Optional

from .base_agent import BaseAgent
from ...state import GraphState
from ..agent_repository import AgentRepository

logger = logging.getLogger(__name__)


class AgenticOrchestrator(BaseAgent):
    """Orchestrator to enuemrate tools and makes decisions."""

    def __init__(self):
        super().__init__("agentic_orchestrator")
        self.agent_repository = AgentRepository()
        self.available_capabilities = self.agent_repository.get_available_capabilities()
        logger.info(f"AgenticOrchestrator initialized with {len(self.available_capabilities)} agent capabilities")


    def get_system_prompt(self) -> str:
        # Generate capability list dynamically from agent repository
        capability_sections = {
            "DATA HANDLING": [
                "fetch_content", "detect_content_type", "parse_misp_content",
                "parse_stix_content", "extract_rss_urls",
                "parse_html_content", "parse_pdf_content", "parse_json_content", "parse_text_content"
            ],
            "CTI PROCESSING": [
                "extract_entities", "extract_iocs", "extract_cves", "map_mitre_ttps",
                "generate_summary", "analyze_geographic_scope", "classify_cyber_relevance",
                "validate_and_complete", "store_results"
            ]
        }

        capabilities_text = ""
        for section, capabilities in capability_sections.items():
            capabilities_text += f"{section}:\n"
            for capability in capabilities:
                description = self.agent_repository.get_capability_description(capability)
                capabilities_text += f"- {capability}: {description}\n"
            capabilities_text += "\n"

        return """You are an autonomous CTI processing agent focused on completing a specific JSON structure.
        
Think about your answer first before you respond. 
The accuracy of your response is very important as this data will be used for operational purposes.
If you don't know the answer, reply with success: false, do not ever try to make up an answer.

YOUR PRIMARY GOAL: Fill this exact JSON structure with extracted threat intelligence:
{
  "title": "",
  "url": "",
  "summary": "",
  "threat_actors": [],
  "malware": [],
  "cve_vulns": [],
  "affected_products": [],
  "iocs": {
    "network": [],
    "host": [],
    "behavioral": []
  },
  "mitre_ttps": [],
  "victims": [],
  "sectors": [],
  "patch_availability": "",
  "affects_singapore": false,
  "affects_asean": false,
  "active_exploitation": false,
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
}

COMPLETION CRITERIA: Processing is complete when ALL major fields are populated and store_results has executed.

AVAILABLE AGENT CAPABILITIES:
""" + capabilities_text.strip() + """

MANDATORY PROCESSING SEQUENCE:
1. fetch_content (ALWAYS FIRST - no exceptions)
2. detect_content_type (ALWAYS AFTER FETCH - determines parsing approach)
3. PARSE CONTENT FIRST (MANDATORY - based on detected type). Choose the best "parser" tool.

THEN ADAPTIVE PROCESSING (ONLY AFTER PARSING):
4. extract_entities → extract_iocs → extract_cves → map_mitre_ttps
5. generate_summary → analyze_geographic_scope → classify_cyber_relevance
6. validate_and_complete → store_results

CRITICAL RULES:
- NEVER skip detect_content_type - even if MIME type seems obvious
- ALWAYS parse content BEFORE any extraction (entities, IOCs, CVEs)
- TEXT content type REQUIRES parse_text_content - no exceptions
- Content type detection determines correct specialized parser
- JSON MIME ≠ generic JSON (could be STIX, MISP, etc.)
- EXTRACTION WILL FAIL without parsed content - parse first!
- RSS FEEDS are SPECIAL: Use extract_rss_urls instead of parse_rss_content
  - extract_rss_urls extracts child URLs from the RSS feed
  - Orchestrator automatically processes each URL through full CTI pipeline
  - Results stored in state.rss_results array
  - After RSS processing completes, mark as complete (no further extraction needed)

RESPOND WITH JSON ONLY:

Agent capability example:
{
  "action": "use_agent",
  "capability": "fetch_content",
  "reasoning": "Start with mandatory fetch step"
}

After fetch, ALWAYS:
{
  "action": "use_agent",
  "capability": "detect_content_type",
  "reasoning": "Mandatory content detection after fetch"
}

For TEXT content, ALWAYS parse first:
{
  "action": "use_agent",
  "capability": "parse_text_content",
  "reasoning": "TEXT content detected, must parse before extraction"
}

For RSS content, extract child URLs first:
{
  "action": "use_agent",
  "capability": "extract_rss_urls",
  "reasoning": "RSS feed detected, extracting child URLs for individual CTI processing"
}

Completion:
{
  "action": "complete",
  "reasoning": "All CTI processing completed using agents"
}

USE ONLY AGENT CAPABILITIES - NO MCP TOOLS AVAILABLE."""

    def decide_next_action(self, state: GraphState) -> Dict[str, Any]:
        """Make autonomous decision about next action based on state and available agent capabilities."""

        # CRITICAL SECURITY: Validate state content before decision-making
        from .guardrails_helper import get_cti_guardrails
        guardrails = get_cti_guardrails()

        # Check parsed content for jailbreak attempts
        if state.parsed and state.parsed.get("text"):
            validation = guardrails.validate_user_input(state.parsed["text"], "agentic_orchestrator")
            if not validation["safe"]:
                logger.error(f"Agentic orchestrator blocked malicious content: {validation['blocked_reasons']}")
                return {"action": "analyze", "reasoning": "Content blocked by security guardrails"}

        # Prepare comprehensive state and agent capabilities information
        analysis_data = self._prepare_analysis_data(state)

        # Debug: Log current state for troubleshooting
        logger.debug(f"State analysis for LLM: has_fetched={analysis_data['current_state']['has_fetched_content']}, "
                    f"content_size={analysis_data['current_state']['fetched_content_size']}, "
                    f"mime={analysis_data['current_state']['fetched_mime_type']}")

        user_prompt = f"""
CURRENT STATE ANALYSIS:
{json.dumps(analysis_data, indent=2)}

As an autonomous CTI processing agent, your PRIMARY GOAL is to complete the target JSON structure:

JSON COMPLETION STATUS:
- Fields Complete: {analysis_data['json_structure_status']['complete_fields']}/{analysis_data['json_structure_status']['total_fields']} ({analysis_data['json_structure_status']['completion_percentage']}%)
- Missing Fields: {analysis_data['json_structure_status']['missing_fields']}
- Structure Complete: {analysis_data['json_structure_status']['structure_complete']}

DECISION CRITERIA:
1. If JSON structure is INCOMPLETE: Focus on agent capabilities that will populate missing fields
2. If JSON structure is COMPLETE: Use store_results then mark as complete
3. NEVER complete without ensuring store_results has executed

ANALYSIS QUESTIONS:
1. What JSON fields are still missing or empty?
2. Which agent capability will populate the most critical missing fields?
3. Have all extraction phases been attempted (entities, IOCs, CVEs, MITRE, geographic)?
4. Has store_results been executed for the completed structure?

RESPONSE PRIORITY:
1. Complete missing essential fields first (title, summary, threat_actors, malware, iocs, mitre_ttps)
2. Then complete analysis fields (geographic scope, active_exploitation, patch_availability)
3. Finally execute store_results and complete

Follow the MANDATORY sequence: fetch → detect_content_type → specialized parsing, then focus on JSON completion.
"""

        try:
            response = self.call_llm(self.get_system_prompt(), user_prompt)

            # Update state token usage with orchestrator's usage
            self.update_state_token_usage(state)

            if not response or not response.strip():
                return {"action": "analyze", "reasoning": "Empty response, need to analyze state"}

            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response.strip(), re.DOTALL)
            if json_match:
                json_text = json_match.group(0)
                decision = json.loads(json_text)
            else:
                return {"action": "analyze", "reasoning": "No valid JSON in response"}

            # Validate decision and enforce mandatory sequence
            action = decision.get("action")
            if action == "use_agent":
                capability = decision.get("capability")
                if not capability or capability not in self.available_capabilities:
                    return {"action": "analyze", "reasoning": f"Agent capability {capability} not available"}

                # Enforce mandatory sequence: fetch_content -> detect_content_type -> parsing
                decision = self._enforce_mandatory_sequence(state, decision)

            elif action not in ["complete", "analyze"]:
                return {"action": "analyze", "reasoning": f"Unknown action: {action}"}

            self.log_processing("Agentic decision made", {
                "action": decision.get("action"),
                "capability": decision.get("capability"),
                "reasoning": decision.get("reasoning", "")
            })

            return decision

        except Exception as e:
            logger.error(f"Decision making failed: {e}")
            return {"action": "analyze", "reasoning": f"Error in decision making: {str(e)}"}

    def execute_decision(self, state: GraphState, decision: Dict[str, Any]) -> GraphState:
        """Execute the decided action and update state."""

        action = decision.get("action")

        if action == "use_agent":
            return self._execute_agent_capability(state, decision)
        elif action == "complete":
            logger.info(f"Processing completed: {decision.get('reasoning')}")
            return state
        elif action == "analyze":
            logger.info(f"Analysis requested: {decision.get('reasoning')}")
            return state
        else:
            logger.warning(f"Unknown action: {action}")
            return state

    def _enforce_mandatory_sequence(self, state: GraphState, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce mandatory processing sequence: fetch -> detect_content_type -> specialized parsing."""
        capability = decision.get("capability")

        # Check current state to determine what's required
        has_fetched = state.fetched is not None
        has_detected_type = state.detected_type is not None

        # Rule 1: If nothing fetched yet, must fetch first
        if not has_fetched and capability != "fetch_content":
            logger.info(f"Enforcing mandatory sequence: forcing fetch_content before {capability}")
            return {
                "action": "use_agent",
                "capability": "fetch_content",
                "reasoning": "Mandatory: must fetch content before any other processing"
            }

        # Rule 2: If fetched but no content type detected, must detect type
        if has_fetched and not has_detected_type and capability not in ["detect_content_type", "fetch_content"]:
            logger.info(f"Enforcing mandatory sequence: forcing detect_content_type before {capability}")
            return {
                "action": "use_agent",
                "capability": "detect_content_type",
                "reasoning": "Mandatory: must detect content type after fetch before parsing"
            }

        # Rule 3: If trying to use generic JSON parsing when STIX detected, redirect to STIX
        if (has_detected_type and state.detected_type == "STIX" and
            capability == "parse_json_content"):
            logger.info("Enforcing STIX-specific parsing instead of generic JSON")
            return {
                "action": "use_agent",
                "capability": "parse_stix_content",
                "reasoning": "Using STIX-specific parser for detected STIX content"
            }

        # Rule 3.5: If RSS content detected, handle RSS feed processing
        if (has_detected_type and state.detected_type == "RSS"):
            # Allow extract_rss_urls to proceed
            if capability == "extract_rss_urls":
                return decision
            elif state.extracted.get("rss_urls_processed"):
                # RSS already processed, mark as complete
                logger.info("RSS URLs already processed, marking as complete")
                return {
                    "action": "complete",
                    "reasoning": f"RSS URLs processed: {state.extracted.get('rss_successful_count', 0)} successful, {state.extracted.get('rss_failed_count', 0)} failed items"
                }
            elif capability not in ["fetch_content", "detect_content_type", "extract_rss_urls"]:
                # Skip other extraction steps for RSS feeds
                logger.info(f"Skipping {capability} for RSS feed, RSS URLs will be processed separately")
                return {
                    "action": "complete",
                    "reasoning": "RSS feeds are URL containers - individual processing handled separately"
                }

        # Rule 4: If cyber classification already attempted, don't do it again
        if (capability == "classify_cyber_relevance" and
            state.extracted.get("cyber_classification_attempted")):
            logger.info("Cyber classification already attempted, skipping duplicate call")
            return {
                "action": "complete",
                "reasoning": "Cyber classification already completed, avoiding duplicate processing"
            }

        # Rule 5: Prevent excessive validation loops
        if capability == "validate_and_complete":
            validation_attempts = state.extracted.get("validation_attempts", 0)
            if validation_attempts >= 2:
                logger.info(f"Validation already attempted {validation_attempts} times, forcing completion")
                return {
                    "action": "complete",
                    "reasoning": f"Validation attempted {validation_attempts} times, preventing excessive loops"
                }
            # Track validation attempts
            state.extracted["validation_attempts"] = validation_attempts + 1

        # Allow the original decision if it follows the sequence
        return decision


    def _execute_agent_capability(self, state: GraphState, decision: Dict[str, Any]) -> GraphState:
        """Execute an agent capability and update state."""

        capability = decision.get("capability")
        reasoning = decision.get("reasoning", "")

        try:
            logger.info(f"Executing agent capability: {capability} - {reasoning}")

            # Get capability method from agent repository
            capability_method = getattr(self.agent_repository, capability, None)
            if not capability_method:
                logger.error(f"Capability {capability} not found in agent repository")
                return state

            # Execute the capability
            state = capability_method(state)

            # Add capability execution to evidence
            state.evidence.append({
                "source": f"agent_capability_{capability}",
                "type": "agent_execution",
                "data": {
                    "capability": capability,
                    "reasoning": reasoning,
                    "description": self.agent_repository.get_capability_description(capability)
                }
            })

            logger.info(f"Agent capability {capability} executed successfully")

        except Exception as e:
            logger.error(f"Agent capability execution failed for {capability}: {e}")
            state.evidence.append({
                "source": f"agent_capability_{capability}",
                "type": "agent_error",
                "data": {"error": str(e)}
            })

        return state


    def _prepare_analysis_data(self, state: GraphState) -> Dict[str, Any]:
        """Prepare comprehensive data for LLM analysis with JSON structure focus."""

        # Analyze JSON structure completeness
        json_status = self._analyze_json_completeness(state)

        data = {
            "url": state.url,
            "json_structure_status": json_status,
            "available_agent_capabilities": [
                {
                    "name": capability,
                    "description": self.agent_repository.get_capability_description(capability)
                }
                for capability in self.available_capabilities
            ],
            "current_state": {
                "has_fetched_content": state.fetched is not None,
                "fetched_content_size": len(state.fetched.get("content_b64", "")) if state.fetched else 0,
                "fetched_mime_type": state.fetched.get("mime") if state.fetched else None,
                "content_type_detected": state.detected_type,
                "content_type_available": state.detected_type or (state.fetched.get("mime") if state.fetched else None),
                "has_parsed_data": state.parsed is not None,
                "extracted_fields": list(state.extracted.keys()),
                "evidence_count": len(state.evidence)
            }
        }

        # Add content samples if available
        if state.fetched:
            data["content_info"] = {
                "size": len(state.fetched.get("content_b64", "")),
                "mime_type": state.fetched.get("mime"),
                "status": state.fetched.get("status")
            }

        if state.parsed and isinstance(state.parsed, dict):
            data["parsed_info"] = {
                "keys": list(state.parsed.keys()),
                "text_length": len(state.parsed.get("text", "")) if state.parsed.get("text") else 0
            }

        # Add extraction status
        data["extraction_status"] = {
            "has_summary": bool(state.extracted.get("summary")),
            "has_threat_actors": bool(state.extracted.get("threat_actors")),
            "has_malware": bool(state.extracted.get("malware")),
            "has_victims": bool(state.extracted.get("victims")),
            "has_sectors": bool(state.extracted.get("sectors")),
            "has_products": bool(state.extracted.get("affected_products")),
            "has_iocs": bool(state.extracted.get("iocs")),
            "has_cves": bool(state.extracted.get("cve_vulns")),
            "entities_extraction_attempted": bool(state.extracted.get("entities_extraction_attempted")),
            "iocs_extraction_attempted": bool(state.extracted.get("iocs_extraction_attempted")),
            "cve_extraction_attempted": bool(state.extracted.get("cve_extraction_attempted")),
            "mitre_ttps_extraction_attempted": bool(state.extracted.get("mitre_ttps_extraction_attempted")),
            "entities_extracted": bool(state.extracted.get("threat_actors") or state.extracted.get("malware") or
                                     state.extracted.get("victims") or state.extracted.get("sectors") or
                                     state.extracted.get("affected_products")),
            "cyber_classified": state.extracted.get("cyber_related") is not None,
            "cyber_classification_attempted": bool(state.extracted.get("cyber_classification_attempted"))
        }

        return data

    def _analyze_json_completeness(self, state: GraphState) -> Dict[str, Any]:
        """Analyze which JSON fields are missing or incomplete."""
        target_structure = {
            "title": {"current": state.extracted.get("title", ""), "required": "string", "populated": bool(str(state.extracted.get("title", "")).strip())},
            "url": {"current": state.extracted.get("url", state.url), "required": "string", "populated": bool(state.extracted.get("url") or state.url)},
            "source_url": {"current": state.extracted.get("source_url", state.url), "required": "string", "populated": bool(state.extracted.get("source_url", state.url))},
            "summary": {"current": state.extracted.get("summary", ""), "required": "string", "populated": bool(str(state.extracted.get("summary", "")).strip())},
            "threat_actors": {"current": state.extracted.get("threat_actors", []), "required": "list", "populated": isinstance(state.extracted.get("threat_actors"), list)},
            "malware": {"current": state.extracted.get("malware", []), "required": "list", "populated": isinstance(state.extracted.get("malware"), list)},
            "cve_vulns": {"current": state.extracted.get("cve_vulns", []), "required": "list", "populated": isinstance(state.extracted.get("cve_vulns"), list)},
            "affected_products": {"current": state.extracted.get("affected_products", []), "required": "list", "populated": isinstance(state.extracted.get("affected_products"), list)},
            "iocs": {"current": state.extracted.get("iocs", {}), "required": "dict", "populated": self._validate_iocs_completeness(state.extracted.get("iocs"), state)},
            "mitre_ttps": {"current": state.extracted.get("mitre_ttps", []), "required": "list", "populated": isinstance(state.extracted.get("mitre_ttps"), list)},
            "victims": {"current": state.extracted.get("victims", []), "required": "list", "populated": isinstance(state.extracted.get("victims"), list)},
            "sectors": {"current": state.extracted.get("sectors", []), "required": "list", "populated": isinstance(state.extracted.get("sectors"), list)},
            "patch_availability": {"current": state.extracted.get("patch_availability", False), "required": "boolean", "populated": isinstance(state.extracted.get("patch_availability"), bool) or isinstance(state.extracted.get("patch_availability"), str)},
            "affects_singapore": {"current": state.extracted.get("affects_singapore", False), "required": "boolean", "populated": state.extracted.get("affects_singapore") is not None},
            "affects_asean": {"current": state.extracted.get("affects_asean", False), "required": "boolean", "populated": state.extracted.get("affects_asean") is not None},
            "active_exploitation": {"current": state.extracted.get("active_exploitation", False), "required": "boolean", "populated": isinstance(state.extracted.get("active_exploitation"), bool)},
            "underlying_causes": {"current": state.extracted.get("underlying_causes", []), "required": "list", "populated": bool(state.extracted.get("underlying_causes"))},
            "strategic_implications": {"current": state.extracted.get("strategic_implications", []), "required": "list", "populated": bool(state.extracted.get("strategic_implications"))},
            "regional_context": {"current": state.extracted.get("regional_context", ""), "required": "string", "populated": bool(str(state.extracted.get("regional_context", "")).strip())},
            "escalation_potential": {"current": state.extracted.get("escalation_potential", ""), "required": "string", "populated": bool(str(state.extracted.get("escalation_potential", "")).strip())},
            "stakeholder_interests": {"current": state.extracted.get("stakeholder_interests", ""), "required": "string", "populated": bool(str(state.extracted.get("stakeholder_interests", "")).strip())}
        }

        missing_fields = [field for field, info in target_structure.items() if not info["populated"]]
        complete_fields = [field for field, info in target_structure.items() if info["populated"]]

        return {
            "total_fields": len(target_structure),
            "complete_fields": len(complete_fields),
            "missing_fields": missing_fields,
            "completion_percentage": round((len(complete_fields) / len(target_structure)) * 100, 1),
            "structure_complete": len(missing_fields) == 0,
            "field_details": target_structure
        }

    def _get_priority_capability_for_missing_fields(self, state: GraphState, json_status: Dict[str, Any]) -> Dict[str, Any]:
        """Determine the highest priority capability to populate missing JSON fields."""
        missing_fields = json_status["missing_fields"]
        logger.info(f"Priority override called with missing_fields: {missing_fields}")

        # CRITICAL: Respect mandatory sequence - cannot do extraction without fetch/detect/parse
        has_fetched = state.fetched is not None
        has_detected_type = state.detected_type is not None
        has_parsed = state.parsed is not None

        if not has_fetched:
            logger.info("Priority override: Must fetch content first")
            return {
                "action": "use_agent",
                "capability": "fetch_content",
                "reasoning": "Mandatory: must fetch content before any processing"
            }

        if not has_detected_type:
            logger.info("Priority override: Must detect content type first")
            return {
                "action": "use_agent",
                "capability": "detect_content_type",
                "reasoning": "Mandatory: must detect content type before extraction"
            }

        # Special handling for RSS feeds - extract URLs then process each one
        if state.detected_type == "RSS":
            if not state.extracted.get("rss_urls_extracted"):
                logger.info("Priority override: RSS feed detected, extracting child URLs")
                return {
                    "action": "use_agent",
                    "capability": "extract_rss_urls",
                    "reasoning": "RSS feeds are containers - extract child URLs for individual processing"
                }
            elif state.extracted.get("rss_urls_processed"):
                # RSS processing is complete, mark as complete
                logger.info("Priority override: RSS URLs processed, marking as complete")
                return {
                    "action": "complete",
                    "reasoning": f"RSS feed processed: {state.extracted.get('rss_successful_count', 0)} successful, {state.extracted.get('rss_failed_count', 0)} failed items"
                }

        if not has_parsed and state.detected_type != "RSS":
            # Need to parse content before extraction (except RSS which handles parsing internally)
            parse_capability_map = {
                "MISP": "parse_misp_content",
                "STIX": "parse_stix_content",
                "HTML": "parse_html_content",
                "PDF": "parse_pdf_content",
                "JSON": "parse_json_content",
                "TEXT": "parse_text_content"
            }
            parse_capability = parse_capability_map.get(state.detected_type, "parse_text_content")
            logger.info(f"Priority override: Must parse {state.detected_type} content first")
            return {
                "action": "use_agent",
                "capability": parse_capability,
                "reasoning": f"Mandatory: must parse {state.detected_type} content before extraction"
            }

        # Priority mapping - which capability populates which fields
        field_capability_map = {
            "title": "generate_summary",  # Summary generation includes title
            "summary": "generate_summary",
            "threat_actors": "extract_entities",
            "malware": "extract_entities",
            "victims": "extract_entities",
            "sectors": "extract_entities",
            "affected_products": "extract_entities",
            "cve_vulns": "extract_cves",
            "iocs": "extract_iocs",
            "mitre_ttps": "map_mitre_ttps",
            "patch_availability": "extract_cves",  # CVE extraction includes patch info
            "affects_singapore": "analyze_geographic_scope",
            "affects_asean": "analyze_geographic_scope",
            "active_exploitation": "extract_cves",  # CVE extraction includes exploitation status
            "underlying_causes": "analyze_geographic_scope",
            "strategic_implications": "analyze_geographic_scope",
            "regional_context": "analyze_geographic_scope",
            "escalation_potential": "analyze_geographic_scope",
            "stakeholder_interests": "analyze_geographic_scope"
        }

        # Priority order for capabilities (most important first)
        capability_priority = [
            "generate_summary",
            "extract_entities",
            "extract_iocs",
            "extract_cves",  # Moved higher to ensure CVE extraction always runs
            "analyze_geographic_scope",
            "map_mitre_ttps"
        ]

        # Mandatory extraction capabilities that should always be attempted regardless of field status
        mandatory_extractions = {
            "extract_cves": "cve_extraction_attempted",
            "extract_entities": "entities_extraction_attempted",
            "extract_iocs": "iocs_extraction_attempted",
            "map_mitre_ttps": "mitre_ttps_extraction_attempted"
        }

        # First, check for mandatory extractions that haven't been attempted
        for capability, attempted_key in mandatory_extractions.items():
            if not state.extracted.get(attempted_key, False):
                # Additional check for CVE extraction - only attempt if we have parsed content
                if capability == "extract_cves" and not (state.parsed and state.parsed.get("text", "").strip()):
                    logger.info("Skipping CVE extraction - no parsed text content available")
                    continue

                return {
                    "action": "use_agent",
                    "capability": capability,
                    "reasoning": f"Mandatory extraction capability {capability} not yet attempted"
                }

        # Then check for missing fields that need specific capabilities
        for capability in capability_priority:
            for field in missing_fields:
                # Handle complex field names like "iocs={'network': [], 'host': [], 'behavioral': []}"
                field_name = field.split('=')[0] if '=' in field else field
                if field_capability_map.get(field_name) == capability:
                    # Check if this capability has already been attempted
                    attempted_key = f"{capability.replace('extract_', '').replace('analyze_', '').replace('map_', '').replace('generate_', '')}_extraction_attempted"
                    if capability == "analyze_geographic_scope":
                        attempted_key = "geographic_analysis_attempted"
                    elif capability == "generate_summary":
                        attempted_key = "summary_generation_attempted"

                    if not state.extracted.get(attempted_key, False):
                        return {
                            "action": "use_agent",
                            "capability": capability,
                            "reasoning": f"Populating missing JSON field '{field}' using {capability}"
                        }
                    else:
                        logger.info(f"Capability {capability} already attempted (flag: {attempted_key}={state.extracted.get(attempted_key)}) for field {field}")

        # If all capabilities have been attempted, return completion
        return {
            "action": "complete",
            "reasoning": "All extraction capabilities attempted, completing with current data"
        }

    def _is_processing_substantially_complete(self, state: GraphState) -> bool:
        """Check if processing has reached a point where storage should occur."""
        return self._is_json_structure_complete(state)

    def _is_json_structure_complete(self, state: GraphState) -> bool:
        """Check if all required JSON fields are populated according to the target structure."""
        # Essential fields that must have meaningful values
        essential_fields = {
            "title": lambda v: bool(str(v).strip()),
            "url": lambda v: bool(str(v).strip()),
            "source_url": lambda v: bool(str(v).strip()),
            "summary": lambda v: bool(str(v).strip()),
            "threat_actors": lambda v: isinstance(v, list),
            "malware": lambda v: isinstance(v, list),
            "cve_vulns": lambda v: isinstance(v, list),
            "affected_products": lambda v: isinstance(v, list),
            "iocs": lambda v: self._validate_iocs_completeness(v, state),
            "mitre_ttps": lambda v: isinstance(v, list),
            "victims": lambda v: isinstance(v, list),
            "sectors": lambda v: isinstance(v, list),
            "patch_availability": lambda v: isinstance(v, bool) or isinstance(v, str),
            "affects_singapore": lambda v: isinstance(v, bool),
            "affects_asean": lambda v: isinstance(v, bool),
            "active_exploitation": lambda v: isinstance(v, bool),
        }

        # Check if basic processing steps are complete
        has_content = state.fetched is not None and state.parsed is not None
        if not has_content:
            return False

        # Check essential fields are properly populated
        missing_fields = []
        for field, validator in essential_fields.items():
            value = state.extracted.get(field)
            if value is None or not validator(value):
                missing_fields.append(f"{field}={value}")

        if missing_fields:
            logger.info(f"JSON structure incomplete - Missing fields: {missing_fields}")
            # If only patch_availability is missing and we have CVE data, consider it complete
            if len(missing_fields) == 1 and missing_fields[0].startswith("patch_availability"):
                if state.extracted.get("cve_extraction_attempted", False):
                    logger.info("CVE extraction attempted, considering patch_availability complete")
                    return True
            return False

        # Verify extraction phases completed
        required_extractions = [
            "entities_extraction_attempted",
            "iocs_extraction_attempted",
            "cve_extraction_attempted",
            "mitre_ttps_extraction_attempted",
            "cyber_classification_attempted"
        ]

        for extraction in required_extractions:
            if not state.extracted.get(extraction, False):
                logger.debug(f"Extraction phase '{extraction}' not completed")
                return False

        logger.info("JSON structure validation: All essential fields populated")
        return True

    def _validate_iocs_completeness(self, iocs_value: Any, state: GraphState) -> bool:
        """Validate IOCs are complete - must have structure and content if STIX patterns exist."""
        # Check basic IOC structure
        if not isinstance(iocs_value, dict):
            return False

        required_keys = ["domains", "ips", "hashes"]
        if not all(k in iocs_value for k in required_keys):
            return False

        # If we have STIX indicator patterns in the parsed text, we need actual IOCs
        parsed_text = state.parsed.get("text", "") if state.parsed else ""
        has_stix_patterns = "STIX_INDICATOR_PATTERN" in parsed_text

        if has_stix_patterns:
            # Check if we have any non-empty IOC lists
            has_actual_iocs = any(
                len(iocs_value.get(field, [])) > 0
                for field in ["domains", "ips", "hashes", "urls"]
            )
            if not has_actual_iocs:
                logger.info("STIX patterns found but no IOCs extracted - IOC extraction needed")
                return False

        return True

    def _process_rss_urls(self, state: GraphState) -> None:
        """Process each RSS URL individually through the full CTI pipeline."""
        from ...graph import process_url

        rss_urls = state.extracted.get("rss_urls", [])
        if not rss_urls:
            logger.warning("No RSS URLs to process")
            state.extracted["rss_urls_processed"] = True
            return

        logger.info(f"Processing {len(rss_urls)} RSS URLs individually")

        # Process each URL
        for i, url_info in enumerate(rss_urls):
            url = url_info.get("url")
            metadata = url_info.get("metadata", {})

            if not url:
                logger.warning(f"RSS URL {i+1} missing URL, skipping")
                continue

            logger.info(f"Processing RSS URL {i+1}/{len(rss_urls)}: {url}")

            try:
                # Process this URL through the full CTI pipeline
                result = process_url(url)

                # Add RSS metadata to the result
                if result.get("success"):
                    enriched_result = {
                        "url": url,
                        "success": True,
                        "data": result["data"],
                        "evidence": result.get("evidence", []),
                        "source_feed": state.url,
                        "item_metadata": metadata,
                        "token_usage": result.get("token_usage", {
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "total_tokens": 0,
                            "processing_time": 0.0,
                            "agents": {}
                        })
                    }
                else:
                    enriched_result = {
                        "url": url,
                        "success": False,
                        "error": result.get("error", "Processing failed"),
                        "source_feed": state.url,
                        "item_metadata": metadata,
                        "token_usage": result.get("token_usage", {
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "total_tokens": 0,
                            "processing_time": 0.0,
                            "agents": {}
                        })
                    }

                # Append to RSS results
                state.rss_results.append(enriched_result)

                # Save RSS item immediately
                if enriched_result.get("success") and enriched_result.get("data"):
                    try:
                        from ...tools.store_emit import store_emit, StoreInput
                        import time
                        import os

                        timestamp = int(time.time())
                        output_dir = os.getenv("OUTPUT_DIR", "./out")
                        rss_filename = f"cti_{timestamp}_{i+1}.json"
                        rss_path = os.path.join(output_dir, rss_filename)

                        store_input = StoreInput(json=enriched_result["data"], path=rss_path, s3=None)
                        store_result = store_emit(store_input)

                        if store_result.written:
                            item_title = metadata.get("title", "RSS Item")[:50]
                            logger.info(f"📁 RSS Item {i+1}/{len(rss_urls)} saved: {item_title}... -> {rss_path}")
                        else:
                            logger.warning(f"Failed to save RSS item {i+1}: {url}")
                    except Exception as save_error:
                        logger.error(f"Error saving RSS item {i+1}: {save_error}")

                # Log completion
                status = "✅ SUCCESS" if enriched_result.get("success") else "❌ FAILED"
                logger.info(f"RSS Item {i+1}/{len(rss_urls)} completed {status}: {url}")

            except Exception as e:
                logger.error(f"Error processing RSS URL {url}: {e}")
                state.rss_results.append({
                    "url": url,
                    "success": False,
                    "error": str(e),
                    "source_feed": state.url,
                    "item_metadata": metadata,
                    "token_usage": {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "total_tokens": 0,
                        "processing_time": 0.0,
                        "agents": {}
                    }
                })

        # Mark RSS URL processing as complete
        successful = len([r for r in state.rss_results if r["success"]])
        failed = len(state.rss_results) - successful

        logger.info(f"RSS URL processing complete: {successful} successful, {failed} failed")
        logger.info(f"DEBUG: state.rss_results has {len(state.rss_results)} items")
        logger.info(f"DEBUG: First RSS result keys: {list(state.rss_results[0].keys()) if state.rss_results else 'No items'}")

        state.extracted["rss_urls_processed"] = True
        state.extracted["rss_item_count"] = len(state.rss_results)
        state.extracted["rss_successful_count"] = successful
        state.extracted["rss_failed_count"] = failed

    def _has_stored_results(self, state: GraphState) -> bool:
        """Check if results have already been stored."""
        # Look for evidence of storage execution in the evidence chain
        for evidence in state.evidence:
            if evidence.get("source", "").startswith("agent_capability_store_results"):
                return True
        return False

    def process(self, state: GraphState) -> GraphState:
        """Main processing method that orchestrates the entire pipeline."""
        import time

        start_time = time.time()
        self.log_agent_start("Starting agentic processing")

        # Defensive check for valid state.url
        if not state.url:
            self.logger.error(f"Invalid state.url: {state.url}. Cannot process with empty URL.")
            return state

        # Initialize url and source_url fields early in processing
        if "url" not in state.extracted or not state.extracted["url"]:
            state.extracted["url"] = state.url
            self.logger.debug(f"Initialized url: {state.url}")

        if "source_url" not in state.extracted or not state.extracted["source_url"]:
            state.extracted["source_url"] = state.url
            self.logger.debug(f"Initialized source_url: {state.url}")

        max_iterations = 30  # Prevent infinite loops
        iterations = 0
        last_action = None
        repeated_count = 0

        while iterations < max_iterations:
            iterations += 1

            # Make decision about next action
            decision = self.decide_next_action(state)

            # Proactive JSON structure checking - override LLM decisions if structure is incomplete
            if not self._is_json_structure_complete(state):
                logger.info("JSON structure incomplete, overriding LLM decision with priority logic")
                json_status = self._analyze_json_completeness(state)
                priority_decision = self._get_priority_capability_for_missing_fields(state, json_status)
                if priority_decision.get("action") != "complete":  # Only override if priority logic has a specific action
                    decision = priority_decision

            # Deterministic completion logic - always check JSON structure first
            if decision.get("action") == "complete":
                # Before completing, verify JSON structure is complete and stored
                if not self._is_json_structure_complete(state):
                    logger.warning("Completion requested but JSON structure incomplete, overriding to continue processing")
                    # Find the most critical missing capability
                    json_status = self._analyze_json_completeness(state)
                    decision = self._get_priority_capability_for_missing_fields(state, json_status)
                elif not self._has_stored_results(state):
                    logger.info("JSON structure complete but not stored, forcing store_results")
                    decision = {"action": "use_agent", "capability": "store_results", "reasoning": "Mandatory storage before completion"}

            # Also check before store_results - don't store incomplete data
            elif decision.get("action") == "use_agent" and decision.get("capability") == "store_results":
                if not self._is_json_structure_complete(state):
                    logger.warning("store_results requested but JSON structure incomplete, overriding to continue processing")
                    # Find the most critical missing capability
                    json_status = self._analyze_json_completeness(state)
                    decision = self._get_priority_capability_for_missing_fields(state, json_status)

            # Check for repeated actions to prevent infinite loops
            current_action = f"{decision.get('action')}_{decision.get('capability', '')}"
            if current_action == last_action:
                repeated_count += 1
                if repeated_count >= 3:  # Allow more attempts since we're being more deterministic
                    logger.warning(f"Action '{current_action}' repeated {repeated_count} times, forcing completion check")
                    # Force final completion logic
                    if self._is_json_structure_complete(state) and self._has_stored_results(state):
                        decision = {"action": "complete", "reasoning": "JSON structure complete and stored - forcing completion"}
                    else:
                        # Force store_results if structure is complete but not stored
                        if self._is_json_structure_complete(state):
                            decision = {"action": "use_agent", "capability": "store_results", "reasoning": "Final storage attempt to break loop"}
                        else:
                            decision = {"action": "complete", "reasoning": "Breaking infinite loop - max iterations reached"}
            else:
                repeated_count = 0
            last_action = current_action

            # Execute the decision
            state = self.execute_decision(state, decision)

            # Special handling for RSS feeds - process extracted URLs
            if (state.extracted.get("rss_urls_extracted") and
                state.extracted.get("rss_urls") and
                not state.extracted.get("rss_urls_processed")):

                logger.info("RSS URLs extracted, processing each URL individually")
                self._process_rss_urls(state)

            # Check if processing is complete
            if decision.get("action") == "complete":
                break

            logger.info(f"Iteration {iterations}: {decision.get('action')} - {decision.get('reasoning', '')}")

        if iterations >= max_iterations:
            logger.warning("Max iterations reached, checking for mandatory final steps")
            # Before stopping, ensure store_results is executed if processing is substantially complete
            if self._is_processing_substantially_complete(state) and not self._has_stored_results(state):
                logger.info("Processing is substantially complete, executing final store_results step")
                try:
                    state = self.agent_repository.store_results(state)
                    logger.info("Final store_results step executed successfully")
                except Exception as e:
                    logger.error(f"Failed to execute final store_results step: {e}")
            logger.warning("Processing stopped after max iterations")

        total_time = time.time() - start_time
        self.log_processing("Agentic processing complete", {
            "iterations": iterations,
            "total_time_seconds": round(total_time, 2),
            "avg_time_per_iteration": round(total_time / iterations if iterations > 0 else 0, 2),
            "final_state": {
                "extracted_fields": list(state.extracted.keys()),
                "evidence_count": len(state.evidence)
            }
        })

        return state