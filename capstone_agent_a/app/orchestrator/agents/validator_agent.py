"""Schema validation and artifact assembly agent."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.schema_validate import validate_and_heal, SchemaInput


class ValidatorAgent(BaseAgent):
    """Agent responsible for final validation and artifact assembly."""

    def __init__(self):
        super().__init__("validator")

    def get_system_prompt(self) -> str:
        return """You are a CTI artifact validation and assembly agent.

Your final responsibility is to:

ARTIFACT ASSEMBLY:
- Combine all extracted data into final CTI artifact
- Ensure all required schema fields are present
- Apply consistent formatting and structure
- Deduplicate array values

SCHEMA VALIDATION:
- Validate against CTI artifact schema
- Heal missing or malformed fields
- Set appropriate default values
- Ensure data type consistency

REQUIRED FIELDS (must all exist):
- title, url, summary
- zero_day_mention, active_exploitation_mentioned
- threat_actors, malware, cve_vulns, cve, affected_products
- iocs (with urls, domains, hashes, ips)
- mitre_ttps
- victims, sectors
- patch_availability, affects_singapore, affects_asean
- high_tension_event
- possible_motivations, recommendations_and_mitigations
- cve_severity, sanitised_html_markdown, cyber_related

FIELD DEFAULTS:
- Arrays: [] (empty array)
- Booleans: false
- Strings: "" (empty string)
- Objects: {} or proper structure for iocs
- null only for sanitised_html_markdown

Ensure final artifact is complete and valid."""

    def process(self, state: GraphState) -> GraphState:
        """Validate and assemble final artifact."""
        try:
            # Prepare final artifact data
            artifact_data = {
                "title": state.extracted.get("title") or state.url,
                "url": state.url,
                "source_url": state.extracted.get("source_url", state.url),
                "summary": state.extracted.get("summary", ""),
                "zero_day_mention": state.extracted.get("zero_day_mention", False),
                "active_exploitation_mentioned": state.extracted.get("active_exploitation_mentioned", False),
                "threat_actors": self._smart_deduplicate(state.extracted.get("threat_actors", [])),
                "malware": self._smart_deduplicate(state.extracted.get("malware", [])),
                "cve_vulns": state.extracted.get("cve_vulns", []),
                "cve": self._deduplicate_cve_products(state.extracted.get("cve", {
                    "vulnerabilities": [],
                    "total_count": 0,
                    "patch_availability": False,
                    "active_exploitation": False,
                    "highest_severity": "UNKNOWN",
                    "highest_cvss": 0.0
                })),
                "affected_products": self._deduplicate_products(state.extracted.get("affected_products", [])),  # Intelligent deduplication
                "iocs": state.extracted.get("iocs", {"urls": [], "domains": [], "hashes": [], "ips": []}),
                "mitre_ttps": self._smart_deduplicate(state.extracted.get("mitre_ttps", [])),  # Added back with deduplication
                "victims": self._smart_deduplicate(state.extracted.get("victims", [])),
                "sectors": self._smart_deduplicate(state.extracted.get("sectors", [])),
                "patch_availability": state.extracted.get("patch_availability", False),
                "affects_singapore": state.extracted.get("affects_singapore", False),
                "affects_asean": state.extracted.get("affects_asean", False),
                "high_tension_event": state.extracted.get("high_tension_event", False),
                "possible_motivations": self._smart_deduplicate(state.extracted.get("possible_motivations", [])),
                "recommendations_and_mitigations": state.extracted.get("recommendations_and_mitigations", ""),
                "cve_severity": state.extracted.get("cve_severity", {}),
                "underlying_causes": state.extracted.get("underlying_causes", []),
                "strategic_implications": state.extracted.get("strategic_implications", []),
                "regional_context": state.extracted.get("regional_context", ""),
                "escalation_potential": state.extracted.get("escalation_potential", ""),
                "stakeholder_interests": state.extracted.get("stakeholder_interests", ""),
                "markdown": state.markdown,
                "cyber_related": state.extracted.get("cyber_related", True)
            }

            # Debug: Log what markdown content we have
            self.logger.info(f"Validator: state.markdown has {len(state.markdown) if state.markdown else 0} characters")
            if state.markdown:
                self.logger.info(f"Validator: First 100 chars: {state.markdown[:100]}")
            else:
                self.logger.warning("Validator: state.markdown is None or empty!")

            # Validate and heal
            schema_input = SchemaInput(json=artifact_data, schema={})
            validation_result = validate_and_heal(schema_input)

            state.extracted = validation_result.healed

            self.log_processing("Artifact validation complete", {
                "validation_ok": validation_result.ok,
                "errors": len(validation_result.errors),
                "fields_count": len(validation_result.healed)
            })

            if validation_result.errors:
                for error in validation_result.errors:  # Log all errors
                    self.logger.warning(f"Validation error: {error['message']}")

            return state

        except Exception as e:
            self.logger.error(f"Error in artifact validation: {e}")
            return state

    def _deduplicate_products(self, products):
        """Deduplicate product list using smart string normalization."""
        if not products or len(products) <= 1:
            return products

        return self._smart_deduplicate(products)

    def _deduplicate_cve_products(self, cve_data):
        """Deduplicate products within CVE vulnerability entries."""
        if not cve_data or "vulnerabilities" not in cve_data:
            return cve_data

        try:
            for vuln in cve_data["vulnerabilities"]:
                if "products" in vuln and len(vuln["products"]) > 1:
                    vuln["products"] = self._smart_deduplicate(vuln["products"])

            self.logger.info(f"Deduplicated products in {len(cve_data['vulnerabilities'])} CVE entries")
            return cve_data
        except Exception as e:
            self.logger.error(f"Error in CVE product deduplication: {e}")
            return cve_data

    def _smart_deduplicate(self, items):
        """Smart deduplication using string normalization and similarity."""
        if not items or len(items) <= 1:
            return items

        import re

        seen = {}
        result = []

        for item in items:
            if not item or not str(item).strip():
                continue

            item_str = str(item).strip()

            # Normalize for comparison: lowercase, remove special chars, collapse whitespace
            normalized = re.sub(r'[_\-\.\s]+', ' ', item_str.lower()).strip()
            normalized = re.sub(r'\s+', ' ', normalized)

            if normalized not in seen:
                seen[normalized] = item_str
                result.append(item_str)
            else:
                # Keep the longer/more complete version
                existing = seen[normalized]
                if len(item_str) > len(existing):
                    # Replace in result with longer version
                    result[result.index(existing)] = item_str
                    seen[normalized] = item_str

        self.logger.info(f"Smart deduplication: {len(items)} -> {len(result)} items")
        return result