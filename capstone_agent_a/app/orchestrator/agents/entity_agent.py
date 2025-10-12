"""Entity extraction agent for threat intelligence."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.nlp import extract_entities, EntitiesInput


class EntityAgent(BaseAgent):
    """Agent responsible for extracting threat intelligence entities."""

    def __init__(self):
        super().__init__("entity")

    def get_system_prompt(self) -> str:
        return """You are a cybersecurity threat intelligence analyst. Extract specific entities from the given text with high precision.

IMPORTANT INSTRUCTIONS:
1. Only extract entities that are EXPLICITLY mentioned in the text
2. Distinguish between ATTACKERS and VICTIMS - don't confuse them
3. For threat actors, look for specific group names, not generic words
4. For affected products, only include software/platforms that are actually targeted or compromised
5. Be very careful not to include legitimate services that are mentioned as targets

Extract the following categories:

THREAT_ACTORS: Named threat groups, APT groups, cybercriminal organizations
- Examples: APT29, UNC6040, Lazarus, ShinyHunters, Fancy Bear, Salt Typhoon
- NOT: generic words like "actors", "groups", "attackers"

MALWARE: Specific malware families, ransomware variants, tools
- Examples: WannaCry, Emotet, Cobalt Strike, TycoonMFA
- NOT: generic terms like "malware", "tools"

VICTIMS: Specific organizations, companies, agencies that were targeted
- Examples: "Acme Corp", "Department of Defense", "Hospital System X"
- NOT: generic terms like "organizations", "companies"

SECTORS: Industry verticals affected
- Examples: Financial, Healthcare, Government, Defense
- Use standard sector names

AFFECTED_PRODUCTS: Software, platforms, systems that were compromised or targeted
- Examples: Salesforce, Office 365, Windows Server
- NOT: legitimate services mentioned only as targets without being compromised

Return ONLY a valid JSON object with these exact keys: threat_actors, malware, victims, sectors, affected_products
Each should be an array of strings. If no entities found for a category, use empty array."""

    def process(self, state: GraphState) -> GraphState:
        """Extract threat intelligence entities using pure LLM analysis."""
        # Set flag immediately to prevent infinite loops
        state.extracted["entities_extraction_attempted"] = True

        try:
            text = state.parsed.get("text", "") if state.parsed else ""

            if not text.strip():
                self.logger.warning("No text content available for entity extraction")
                self._set_empty_entities(state)
                return state

            # Use intelligent text processing for LLM input
            from .text_processor import prepare_llm_input
            text_data = prepare_llm_input(text, agent_type="entity")

            # Create user prompt for entity extraction
            user_input = f"""Analyze this threat intelligence text and extract entities:

{text_data['text']}"""

            # Use LLM to extract entities with the system prompt
            llm_response = self.call_llm(self.get_system_prompt(), user_input)

            # Parse LLM response as JSON
            try:
                import json
                import re

                # Extract JSON from response
                json_match = re.search(r'```json\s*\n(.*?)\n```', llm_response, re.DOTALL)
                if not json_match:
                    # Try to find JSON without code blocks
                    json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)

                if json_match:
                    json_text = json_match.group(1) if json_match.group(0).startswith('```') else json_match.group(0)
                    llm_result = json.loads(json_text)

                    # Extract and validate entities from LLM response
                    threat_actors = self._clean_entity_list(llm_result.get("threat_actors", []))
                    malware = self._clean_entity_list(llm_result.get("malware", []))
                    victims = self._clean_entity_list(llm_result.get("victims", []))
                    sectors = self._clean_entity_list(llm_result.get("sectors", []))
                    products = self._clean_entity_list(llm_result.get("affected_products", []))

                    # Generate evidence snippets for found entities
                    evidence = self._extract_entity_evidence(text, threat_actors + malware + victims + sectors + products)

                else:
                    raise ValueError("No valid JSON found in LLM response")

            except (json.JSONDecodeError, ValueError, KeyError) as e:
                self.logger.warning(f"Could not parse LLM JSON response: {e}")
                # If LLM fails completely, return empty results rather than hardcoded patterns
                threat_actors, malware, victims, sectors, products, evidence = [], [], [], [], [], []

            # Store results in state
            state.extracted["threat_actors"] = threat_actors
            state.extracted["malware"] = malware
            state.extracted["victims"] = victims
            state.extracted["sectors"] = sectors
            state.extracted["affected_products"] = products
            state.extracted["entities_extraction_attempted"] = True  # Mark that extraction was attempted
            state.evidence.extend(evidence)

            self.log_processing("Entity extraction complete", {
                "threat_actors": len(threat_actors),
                "malware": len(malware),
                "victims": len(victims),
                "sectors": len(sectors),
                "products": len(products),
                "method": "llm_only",
                "token_usage": self.token_usage
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in entity extraction: {e}")
            self._set_empty_entities(state)
            return state

    def _clean_entity_list(self, entities):
        """Clean and validate entity list with smart deduplication."""
        if not entities:
            return []

        # Basic cleaning first
        cleaned = []
        for entity in entities:
            if entity and str(entity).strip():
                cleaned_entity = str(entity).strip()
                if len(cleaned_entity) > 1:  # Minimum length check
                    cleaned.append(cleaned_entity)

        # Use smart deduplication
        if len(cleaned) > 1:
            return self._smart_deduplicate_entities(cleaned)
        else:
            return cleaned

    def _smart_deduplicate_entities(self, entities):
        """Smart deduplication using string normalization."""
        import re

        seen = {}
        result = []

        for entity in entities:
            if not entity or not str(entity).strip():
                continue

            entity_str = str(entity).strip()

            # Normalize for comparison: lowercase, remove special chars, collapse whitespace
            normalized = re.sub(r'[_\-\.\s]+', ' ', entity_str.lower()).strip()
            normalized = re.sub(r'\s+', ' ', normalized)

            if normalized not in seen:
                seen[normalized] = entity_str
                result.append(entity_str)
            else:
                # Keep the longer/more complete version
                existing = seen[normalized]
                if len(entity_str) > len(existing):
                    # Replace in result with longer version
                    result[result.index(existing)] = entity_str
                    seen[normalized] = entity_str

        self.logger.info(f"Smart entity deduplication: {len(entities)} -> {len(result)} entities")
        return result

    def _extract_entity_evidence(self, text, entities):
        """Extract evidence snippets for found entities."""
        evidence = []
        for entity in entities:  # No arbitrary limit - process all entities
            if entity.lower() in text.lower():
                start_pos = text.lower().find(entity.lower())
                start = max(0, start_pos - 50)
                end = min(len(text), start_pos + len(entity) + 50)
                snippet = text[start:end].strip()

                # Clean up snippet
                import re
                snippet = re.sub(r'\s+', ' ', snippet)
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."

                evidence.append({
                    "loc": "body",
                    "text": f"[Entity: {entity}] {snippet}"
                })
        return evidence

    def _set_empty_entities(self, state: GraphState):
        """Set empty entity lists in state."""
        state.extracted["threat_actors"] = []
        state.extracted["malware"] = []
        state.extracted["victims"] = []
        state.extracted["sectors"] = []
        state.extracted["affected_products"] = []
        state.extracted["entities_extraction_attempted"] = True  # Mark that extraction was attempted