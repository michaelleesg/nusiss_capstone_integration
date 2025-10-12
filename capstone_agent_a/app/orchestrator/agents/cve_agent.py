"""CVE extraction and enrichment agent."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.cve import extract_from_text, enrich, CVEExtractInput, CVEEnrichInput


class CVEAgent(BaseAgent):
    """Agent responsible for CVE extraction and enrichment."""

    def __init__(self):
        super().__init__("cve")

    def get_system_prompt(self) -> str:
        return """You are a CVE (Common Vulnerabilities and Exposures) analysis agent with context-awareness capabilities.

Your primary responsibility is to categorize CVEs by their relevance to the main threat intelligence topic:

CVE RELEVANCE CATEGORIZATION:
For each CVE identified in the content, assess its contextual relevance:

1. PRIMARY (score 1.0):
   - Main focus of the article/report
   - Currently being exploited or disclosed
   - Central to the threat being discussed
   - New vulnerabilities being announced

2. RELATED (score 0.7-0.9):
   - Directly related to the primary threat
   - Part of the same attack chain
   - Similar vulnerability in same product/vendor
   - Recent vulnerabilities with tactical relevance

3. CONTEXTUAL (score 0.3-0.6):
   - Mentioned for comparison purposes
   - Historical context (e.g., "similar to Heartbleed")
   - Background information
   - Related but not central to current threat

4. REFERENCE (score 0.1-0.2):
   - Passing mentions
   - General examples
   - Unrelated historical references
   - Citations without tactical relevance

RESPONSE FORMAT:
Provide a JSON object categorizing each CVE:
{
  "cve_analysis": [
    {
      "cve_id": "CVE-2024-1234",
      "relevance_score": 1.0,
      "category": "primary",
      "reasoning": "Main vulnerability disclosed in this advisory"
    },
    {
      "cve_id": "CVE-2014-0160",
      "relevance_score": 0.3,
      "category": "contextual",
      "reasoning": "Mentioned as historical comparison (Heartbleed reference)"
    }
  ]
}

GUIDELINES:
- Be strict: Most articles focus on 1-3 primary CVEs
- Historical references (e.g., Heartbleed, Log4Shell) are usually contextual
- CVEs in different products/vendors than main topic are likely references
- Publication date context matters: old CVEs in recent articles are usually background"""

    def process(self, state: GraphState) -> GraphState:
        """Extract and enrich CVEs using LLM-guided analysis."""
        try:
            # Try multiple sources for text content
            text = ""

            # First try parsed text
            if state.parsed:
                text = state.parsed.get("text", "")
                self.logger.debug(f"Debug - parsed text length: {len(text)} chars")

            # Also try markdown field as fallback
            if not text.strip() and hasattr(state, 'markdown') and state.markdown:
                text = state.markdown
                self.logger.info(f"Using markdown content for CVE analysis - {len(text)} chars")

            # If no parsed text, try raw content from fetched
            if not text.strip() and state.fetched:
                import base64
                try:
                    content_bytes = base64.b64decode(state.fetched["content_b64"])
                    text = content_bytes.decode('utf-8', errors='ignore')
                    self.logger.info(f"Using raw content for CVE analysis (parsed text was empty) - {len(text)} chars")
                except Exception as e:
                    self.logger.warning(f"Could not decode raw content: {e}")

            if not text.strip():
                self.logger.warning("No text content available for CVE analysis")
                self.logger.debug(f"Debug - state.parsed: {state.parsed if state.parsed else 'None'}")
                self.logger.debug(f"Debug - state.parsed keys: {list(state.parsed.keys()) if state.parsed else 'None'}")
                self.logger.debug(f"Debug - state.fetched: {bool(state.fetched)}")

                # Show what's available in parsed text specifically
                if state.parsed and 'text' in state.parsed:
                    parsed_text = state.parsed.get('text', '')
                    self.logger.debug(f"Debug - parsed text length: {len(parsed_text)} chars, first 100: '{parsed_text[:100]}'")

                self.logger.debug(f"Debug - state.extracted summary: {state.extracted.get('summary', 'NO_SUMMARY')[:100] if state.extracted else 'NO_EXTRACTED'}")

                # Try to extract CVEs from summary as fallback
                if state.extracted and state.extracted.get('summary'):
                    summary_text = state.extracted.get('summary', '')
                    self.logger.info(f"Fallback: attempting CVE extraction from summary ({len(summary_text)} chars)")
                    text = summary_text
                else:
                    self._set_empty_cves(state)
                    return state

            # Use intelligent text processing for LLM input
            from .text_processor import prepare_llm_input
            text_data = prepare_llm_input(text, agent_type="cve")

            # Create user prompt with the intelligently processed content
            user_input = f"""
Analyze the following threat intelligence content for CVEs (Common Vulnerabilities and Exposures):

Processing Strategy: {text_data['processing_strategy']}
Original Content Length: {text_data['original_tokens']} tokens
Processed Content Length: {text_data['processed_tokens']} tokens

Content:
{text_data['text']}
"""

            # Extract CVEs directly from text using regex patterns (fast, comprehensive)
            import re
            from ...tools.cve import extract_cves_from_text

            # Extract ALL CVE identifiers using pattern matching
            cve_ids = list(extract_cves_from_text(text))

            if not cve_ids:
                self.logger.info("No CVEs found in text")
                self._set_empty_cves(state)
                return state

            # Use LLM to categorize CVEs by contextual relevance
            cve_list_str = ", ".join(cve_ids)
            user_input_with_cves = f"""{user_input}

EXTRACTED CVEs (from regex): {cve_list_str}

Your task: Categorize each of these {len(cve_ids)} CVEs by relevance to the main threat intelligence topic.
Provide the response in the specified JSON format."""

            llm_response = self.call_llm(self.get_system_prompt(), user_input_with_cves)

            # Parse LLM response to extract relevance categorization
            cve_relevance_map = {}
            try:
                import json
                # Try to extract JSON from response
                json_match = re.search(r'```json\s*\n(.*?)\n```', llm_response, re.DOTALL)
                if not json_match:
                    json_match = re.search(r'\{.*"cve_analysis".*\}', llm_response, re.DOTALL)

                if json_match:
                    json_text = json_match.group(1) if json_match.group(0).startswith('```') else json_match.group(0)
                    llm_data = json.loads(json_text)

                    for cve_item in llm_data.get("cve_analysis", []):
                        cve_id = cve_item.get("cve_id", "").upper()
                        if cve_id:
                            cve_relevance_map[cve_id] = {
                                "relevance_score": cve_item.get("relevance_score", 1.0),
                                "category": cve_item.get("category", "primary"),
                                "reasoning": cve_item.get("reasoning", "")
                            }

                    self.logger.info(f"LLM categorized {len(cve_relevance_map)} CVEs by relevance")
                else:
                    self.logger.warning("Could not parse JSON from LLM response, treating all CVEs as primary")

            except Exception as parse_error:
                self.logger.warning(f"Error parsing LLM categorization: {parse_error}, treating all CVEs as primary")

            # Create extract result object with relevance scores
            from ...tools.cve import CVEExtractOutput, StructuredCVE
            cve_objects = []
            for cve_id in cve_ids:
                relevance_data = cve_relevance_map.get(cve_id, {
                    "relevance_score": 1.0,
                    "category": "primary",
                    "reasoning": "No LLM categorization available"
                })
                cve_objects.append(StructuredCVE(
                    value=cve_id,
                    confidence=0.95,
                    source="regex_pattern",
                    relevance_score=relevance_data["relevance_score"],
                    relevance_category=relevance_data["category"],
                    relevance_reasoning=relevance_data["reasoning"]
                ))

            cve_extract_result = CVEExtractOutput(cves=cve_objects)

            # Filter CVEs by relevance threshold (>= 0.5 means primary, related, or high contextual)
            high_relevance_cves = [cve for cve in cve_objects if cve.relevance_score >= 0.5]
            low_relevance_cves = [cve for cve in cve_objects if cve.relevance_score < 0.5]

            self.logger.info(
                f"CVE relevance filtering: {len(high_relevance_cves)} high-relevance "
                f"(will enrich), {len(low_relevance_cves)} low-relevance (will skip enrichment)"
            )

            if cve_extract_result.cves:
                # Only enrich high-relevance CVEs (>= 0.5) to save time and API calls
                high_relevance_cve_ids = [cve.value for cve in high_relevance_cves]
                all_cve_ids = [cve.value for cve in cve_extract_result.cves]

                # Always use online NVD API - do not use offline cache
                if high_relevance_cve_ids:
                    self.logger.info(f"Enriching {len(high_relevance_cve_ids)} high-relevance CVEs using online NVD API")

                    # Enrich CVEs with additional data - always use online
                    cve_enrich_input = CVEEnrichInput(cves=high_relevance_cve_ids, prefer_offline_cache=False)
                    cve_enrich_result = enrich(cve_enrich_input)
                else:
                    self.logger.info("No high-relevance CVEs to enrich")
                    cve_enrich_result = None

                # Create individual CVE objects with all their data
                cve_details = []
                for cve_obj in cve_extract_result.cves:
                    cve_id = cve_obj.value

                    # Check if this CVE was enriched
                    if cve_enrich_result and cve_id in high_relevance_cve_ids:
                        # High-relevance CVE with NVD enrichment
                        cve_details.append({
                            "id": cve_id,
                            "severity": getattr(cve_enrich_result, 'severity', {}).get(cve_id, "UNKNOWN"),
                            "cvss_score": getattr(cve_enrich_result, 'cvss_score', {}).get(cve_id, 0.0),
                            "patch_available": getattr(cve_enrich_result, 'patch_available', {}).get(cve_id, False),
                            "active_exploitation": getattr(cve_enrich_result, 'active_exploitation', {}).get(cve_id, False),
                            "products": getattr(cve_enrich_result, 'products', {}).get(cve_id, []),
                            "cpe_strings": getattr(cve_enrich_result, 'cpe_strings', {}).get(cve_id, []),
                            "affected_versions": getattr(cve_enrich_result, 'affected_versions', {}).get(cve_id, []),
                            "relevance_score": cve_obj.relevance_score,
                            "relevance_category": cve_obj.relevance_category,
                            "relevance_reasoning": cve_obj.relevance_reasoning
                        })
                    else:
                        # Low-relevance CVE without enrichment (saves time and API calls)
                        cve_details.append({
                            "id": cve_id,
                            "severity": "NOT_ENRICHED",
                            "cvss_score": 0.0,
                            "patch_available": False,
                            "active_exploitation": False,
                            "products": [],
                            "cpe_strings": [],
                            "affected_versions": [],
                            "relevance_score": cve_obj.relevance_score,
                            "relevance_category": cve_obj.relevance_category,
                            "relevance_reasoning": cve_obj.relevance_reasoning
                        })

                # Group CVE data into single object
                state.extracted["cve"] = {
                    "vulnerabilities": cve_details,
                    "total_count": len(all_cve_ids),
                    "enriched_count": len(high_relevance_cve_ids),
                    "not_enriched_count": len(low_relevance_cves),
                    "patch_availability": any(cve_enrich_result.patch_available.values()) if cve_enrich_result else False,
                    "active_exploitation": any(cve_enrich_result.active_exploitation.values()) if cve_enrich_result else False,
                    "highest_severity": self._get_highest_severity(cve_enrich_result.severity.values()) if cve_enrich_result else "UNKNOWN",
                    "highest_cvss": max(cve_enrich_result.cvss_score.values()) if cve_enrich_result and cve_enrich_result.cvss_score else 0.0
                }

                # Legacy fields for backward compatibility (only include high-relevance CVEs)
                state.extracted["cve_vulns"] = high_relevance_cve_ids if high_relevance_cve_ids else all_cve_ids
                state.extracted["patch_availability"] = any(getattr(cve_enrich_result, 'patch_available', {}).values()) if cve_enrich_result else False
                state.extracted["cve_extraction_attempted"] = True

                # Initialize affected_products if not present
                if "affected_products" not in state.extracted:
                    state.extracted["affected_products"] = []

                # Add products from CVE enrichment (only for enriched CVEs)
                if cve_enrich_result:
                    for products in getattr(cve_enrich_result, 'products', {}).values():
                        state.extracted["affected_products"].extend(products)

                # Generate evidence for found CVEs (all CVEs, including low-relevance)
                evidence = []
                for cve_obj in cve_extract_result.cves:
                    cve_id = cve_obj.value
                    if cve_id in text:
                        start_pos = text.find(cve_id)
                        start = max(0, start_pos - 50)
                        end = min(len(text), start_pos + len(cve_id) + 50)
                        snippet = text[start:end].strip()
                        if len(snippet) > 200:
                            snippet = snippet[:200] + "..."
                        evidence.append({
                            "loc": "body",
                            "text": snippet,
                            "relevance": cve_obj.relevance_category
                        })

                state.evidence.extend(evidence)

                self.log_processing("CVE analysis complete using LLM-guided relevance filtering", {
                    "total_cves": len(cve_extract_result.cves),
                    "high_relevance": len(high_relevance_cves),
                    "low_relevance": len(low_relevance_cves),
                    "enriched": len(high_relevance_cve_ids),
                    "patch_available": state.extracted["patch_availability"],
                    "active_exploitation": state.extracted["cve"]["active_exploitation"],
                    "products_added": sum(len(p) for p in cve_enrich_result.products.values()) if cve_enrich_result else 0,
                    "token_usage": self.token_usage
                })

            else:
                # No CVEs found
                self._set_empty_cves(state)

            return state

        except Exception as e:
            self.logger.error(f"Error in LLM-guided CVE analysis: {e}", exc_info=True)
            # Fallback: store basic CVE IDs if we found them during extraction
            if 'cve_ids' in locals() and cve_ids:
                self.logger.info(f"Fallback: storing {len(cve_ids)} CVEs without enrichment")
                state.extracted["cve_vulns"] = cve_ids
                state.extracted["patch_availability"] = False  # Unknown without enrichment
                state.extracted["active_exploitation"] = False  # Unknown without enrichment
                state.extracted["cve_extraction_attempted"] = True

                # Store basic CVE structure
                state.extracted["cve"] = {
                    "vulnerabilities": [{"id": cve_id, "severity": "UNKNOWN", "cvss_score": 0.0} for cve_id in cve_ids],
                    "total_count": len(cve_ids),
                    "patch_availability": False,
                    "active_exploitation": False,
                    "highest_severity": "UNKNOWN",
                    "highest_cvss": 0.0
                }

                self.log_processing("CVE fallback extraction complete", {"cves": len(cve_ids)})
                return state

            # Fallback to tool-only extraction
            try:
                text = state.parsed.get("text", "") if state.parsed else ""
                self.logger.info("Attempting fallback CVE extraction without LLM processing")
                cve_extract_input = CVEExtractInput(text=text)
                cve_extract_result = extract_from_text(cve_extract_input)

                if cve_extract_result.cves:
                    # Use NVD enrichment in fallback as well
                    cve_enrich_input = CVEEnrichInput(cves=cve_extract_result.cves, prefer_offline_cache=False)
                    cve_enrich_result = enrich(cve_enrich_input)

                    # Create individual CVE objects with all their data
                    cve_details = []
                    for cve_id in cve_extract_result.cves:
                        cve_details.append({
                            "id": cve_id,
                            "severity": cve_enrich_result.severity.get(cve_id, "UNKNOWN"),
                            "cvss_score": cve_enrich_result.cvss_score.get(cve_id, 0.0),
                            "patch_available": cve_enrich_result.patch_available.get(cve_id, False),
                            "active_exploitation": cve_enrich_result.active_exploitation.get(cve_id, False),
                            "products": cve_enrich_result.products.get(cve_id, []),
                            "cpe_strings": cve_enrich_result.cpe_strings.get(cve_id, []),
                            "affected_versions": cve_enrich_result.affected_versions.get(cve_id, [])
                        })

                    # Group CVE data into single object
                    state.extracted["cve"] = {
                        "vulnerabilities": cve_details,
                        "total_count": len(cve_extract_result.cves),
                        "patch_availability": any(getattr(cve_enrich_result, 'patch_available', {}).values()),
                        "active_exploitation": any(getattr(cve_enrich_result, 'active_exploitation', {}).values()),
                        "highest_severity": self._get_highest_severity(getattr(cve_enrich_result, 'severity', {}).values()),
                        "highest_cvss": max(getattr(cve_enrich_result, 'cvss_score', {}).values()) if getattr(cve_enrich_result, 'cvss_score', {}) else 0.0
                    }

                    # Legacy fields for backward compatibility
                    state.extracted["cve_vulns"] = cve_extract_result.cves
                    state.extracted["patch_availability"] = any(getattr(cve_enrich_result, 'patch_available', {}).values())

                    if "affected_products" not in state.extracted:
                        state.extracted["affected_products"] = []
                    for products in getattr(cve_enrich_result, 'products', {}).values():
                        state.extracted["affected_products"].extend(products)
                else:
                    self._set_empty_cves(state)
            except Exception as fallback_error:
                self.logger.error(f"Fallback CVE analysis also failed: {fallback_error}")
                self._set_empty_cves(state)

            return state

    def _get_highest_severity(self, severities):
        """Get the highest severity level from a list of severities."""
        severity_order = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        highest = "UNKNOWN"
        for severity in severities:
            if severity in severity_order:
                if severity_order.index(severity) > severity_order.index(highest):
                    highest = severity
        return highest

    def _set_empty_cves(self, state: GraphState):
        """Set empty CVE data in state."""
        state.extracted["cve"] = {
            "vulnerabilities": [],
            "total_count": 0,
            "patch_availability": False,
            "active_exploitation": False,
            "highest_severity": "UNKNOWN",
            "highest_cvss": 0.0
        }
        # Legacy fields for backward compatibility
        state.extracted["cve_vulns"] = []
        state.extracted["patch_availability"] = False
        state.extracted["cve_extraction_attempted"] = True