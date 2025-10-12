"""Geographic scope and motivation analysis agent."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.nlp import (
    classify_geo_scope, GeoInput,
    classify_high_tension, TensionInput,
    classify_motivation, MotivationInput
)


class GeoMotivationAgent(BaseAgent):
    """Agent responsible for geographic scope and motivation analysis."""

    def __init__(self):
        super().__init__("geo_motivation")

    def get_system_prompt(self) -> str:
        return """You are a geographic scope, threat actor motivation, and geopolitical implications analysis specialist with deep knowledge of international relations, regional security dynamics, and cyber threat landscapes.

ANALYSIS OBJECTIVES:
1. Assess geographic scope and regional impact
2. Determine threat actor motivations and objectives
3. Analyze geopolitical implications and underlying causes
4. Provide strategic context for decision-making

GEOGRAPHIC SCOPE ANALYSIS:
- Singapore impact: Direct mentions of Singapore, .sg domains, local agencies (CSA, MHA, GovTech), Singapore-based organizations
- ASEAN impact: Southeast Asia region, ASEAN member states, regional infrastructure, cross-border implications
- Global scope: International implications, major power involvement, worldwide targeting patterns
- Note: If Singapore is affected, ASEAN is also considered affected due to regional interconnectedness

HIGH TENSION EVENTS CLASSIFICATION:
- Nation-state sponsored activities
- Critical infrastructure targeting (energy, finance, telecommunications, water, transport)
- Election interference and democratic process disruption
- Government and military system compromises
- Cyber warfare and offensive cyber operations
- Supply chain attacks with national security implications
- Attacks during periods of heightened geopolitical tension

THREAT ACTOR MOTIVATIONS:
- Financial: Ransomware operations, banking fraud, cryptocurrency theft, financial market manipulation
- Espionage: Intelligence gathering, state secrets theft, industrial espionage, military technology theft
- Hacktivism: Political protests, ideological campaigns, social justice movements, anti-government activities
- Extortion: Blackmail operations, coercive threats, intimidation campaigns
- Sabotage: Infrastructure disruption, destructive attacks, operational technology targeting
- Destabilization: Social unrest promotion, trust undermining, chaos creation
- Unknown/Mixed: Unclear objectives or multiple overlapping motivations

GEOPOLITICAL IMPLICATIONS ANALYSIS:
Analyze and provide commentary on:

1. UNDERLYING CAUSES:
   - Regional tensions and territorial disputes
   - Economic competition and trade conflicts
   - Historical grievances and diplomatic tensions
   - Resource competition (energy, technology, data)
   - Ideological differences and governance models
   - Military modernization and arms races

2. STRATEGIC IMPLICATIONS:
   - Impact on regional stability and security
   - Effects on international alliances and partnerships
   - Influence on diplomatic relations
   - Economic and trade relationship impacts
   - Military and defense cooperation effects
   - Technology transfer and cybersecurity implications

3. POTENTIAL ESCALATION PATHWAYS:
   - Risk of cyber incident escalation to physical conflict
   - Possibility of triggering collective defense mechanisms
   - Economic retaliation and sanctions potential
   - Diplomatic crisis development scenarios
   - Regional arms race acceleration
   - Alliance restructuring implications

4. CONTEXTUAL FACTORS:
   - Current regional political climate
   - Ongoing diplomatic initiatives or tensions
   - Economic interdependencies and vulnerabilities
   - Historical precedents and patterns
   - Third-party state interests and involvement
   - International law and norm implications

RESPONSE FORMAT:
Respond with a JSON object containing:
{
  "geographic_scope": {
    "affects_singapore": true/false,
    "affects_asean": true/false,
    "global_implications": true/false,
    "primary_regions_affected": ["Southeast Asia", "East Asia", ...]
  },
  "tension_assessment": {
    "high_tension_event": true/false,
    "tension_level": "low/medium/high/critical",
    "escalation_risk": "low/medium/high"
  },
  "motivations": {
    "primary_motivation": "financial/espionage/hacktivism/extortion/sabotage/destabilization",
    "secondary_motivations": [...],
    "confidence_level": "low/medium/high"
  },
  "geopolitical_analysis": {
    "underlying_causes": [
      "Brief description of root causes and contributing factors"
    ],
    "strategic_implications": [
      "Analysis of broader strategic consequences"
    ],
    "regional_context": "Description of relevant regional political/security dynamics",
    "escalation_potential": "Assessment of risk for conflict escalation",
    "historical_precedents": "Relevant historical context or similar incidents",
    "stakeholder_interests": "Analysis of various state and non-state actor interests"
  },
  "evidence": [
    {"category": "geographic", "text": "Evidence snippet supporting geographic assessment"},
    {"category": "motivation", "text": "Evidence snippet supporting motivation analysis"},
    {"category": "geopolitical", "text": "Evidence snippet supporting geopolitical implications"}
  ],
  "confidence": "low/medium/high",
  "reasoning": "Explanation of analysis methodology and key factors considered"
}

QUALITY STANDARDS:
- Provide nuanced geopolitical analysis based on evidence
- Consider multiple perspectives and stakeholder interests
- Distinguish between immediate and long-term implications
- Assess uncertainty and alternative interpretations
- Ground analysis in observable evidence from the content
- Avoid speculation beyond what evidence supports"""

    def process(self, state: GraphState) -> GraphState:
        """Analyze geographic scope and motivation using LLM-guided analysis."""
        try:
            text = state.parsed.get("text", "") if state.parsed else ""

            if not text.strip():
                self.logger.warning("No text content available for geo/motivation analysis")
                self._set_empty_geo_motivation(state)
                return state

            # Use intelligent text processing for LLM input
            from .text_processor import prepare_llm_input
            text_data = prepare_llm_input(text, agent_type="geo_motivation")

            # Build context from extracted entities
            threat_actors = state.extracted.get("threat_actors", [])
            malware = state.extracted.get("malware", [])
            sectors = state.extracted.get("sectors", [])

            context_info = []
            if threat_actors:
                context_info.append(f"Known Threat Actors: {', '.join(threat_actors)}")
            if malware:
                context_info.append(f"Malware: {', '.join(malware)}")
            if sectors:
                context_info.append(f"Affected Sectors: {', '.join(sectors)}")

            context_text = "\n".join(context_info) if context_info else "No specific threat entities identified."

            # Create user prompt with the intelligently processed content
            user_input = f"""
Analyze this threat intelligence content for geographic scope, motivations, and geopolitical implications:

THREAT CONTEXT:
{context_text}

CONTENT TO ANALYZE:
{text_data['text']}

INSTRUCTIONS:
1. Assess geographic scope and regional impact
2. Determine threat actor motivations with supporting evidence
3. Analyze geopolitical implications, underlying causes, and strategic context
4. Consider regional security dynamics and potential escalation risks
5. Provide evidence-based assessment avoiding speculation

Provide your analysis in the specified JSON format with comprehensive geopolitical commentary.
"""

            # Use LLM to guide analysis with the system prompt
            llm_response = self.call_llm(self.get_system_prompt(), user_input)

            # Parse LLM response for insights
            # Initialize variables
            affects_singapore = False
            affects_asean = False
            global_implications = False
            primary_regions_affected = []
            high_tension = False
            tension_level = "low"
            escalation_risk = "low"
            primary_motivation = "unknown"
            secondary_motivations = []
            geopolitical_analysis = {}
            evidence = []
            confidence = "medium"
            reasoning = ""

            try:
                import json
                import re

                # Extract JSON from response
                json_match = re.search(r'```json\s*\n(.*?)\n```', llm_response, re.DOTALL)
                if not json_match:
                    json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)

                if json_match:
                    json_text = json_match.group(1) if json_match.group(0).startswith('```') else json_match.group(0)
                    llm_result = json.loads(json_text)

                    # Extract geographic scope
                    geo_scope = llm_result.get("geographic_scope", {})
                    affects_singapore = geo_scope.get("affects_singapore", False)
                    affects_asean = geo_scope.get("affects_asean", False)
                    global_implications = geo_scope.get("global_implications", False)
                    primary_regions_affected = geo_scope.get("primary_regions_affected", [])

                    # Extract tension assessment
                    tension_assessment = llm_result.get("tension_assessment", {})
                    high_tension = tension_assessment.get("high_tension_event", False)
                    tension_level = tension_assessment.get("tension_level", "low")
                    escalation_risk = tension_assessment.get("escalation_risk", "low")

                    # Extract motivations
                    motivations_data = llm_result.get("motivations", {})
                    primary_motivation = motivations_data.get("primary_motivation", "unknown")
                    secondary_motivations = motivations_data.get("secondary_motivations", [])

                    # Extract geopolitical analysis
                    geopolitical_analysis = llm_result.get("geopolitical_analysis", {})

                    # Extract evidence
                    evidence = llm_result.get("evidence", [])
                    if isinstance(evidence, list):
                        formatted_evidence = []
                        for ev in evidence:
                            if isinstance(ev, dict) and "text" in ev:
                                formatted_evidence.append({
                                    "loc": "body",
                                    "text": ev["text"],
                                    "category": ev.get("category", "general")
                                })
                            elif isinstance(ev, str):
                                formatted_evidence.append({"loc": "body", "text": ev})
                        evidence = formatted_evidence

                    # Extract confidence and reasoning
                    confidence = llm_result.get("confidence", "medium")
                    reasoning = llm_result.get("reasoning", "")

                else:
                    raise ValueError("No valid JSON found in LLM response")

            except (json.JSONDecodeError, ValueError):
                # Fallback to tool-based analysis if LLM doesn't provide JSON
                geo_input = GeoInput(text=text)
                geo_result = classify_geo_scope(geo_input)
                affects_singapore = geo_result.affects_singapore
                affects_asean = geo_result.affects_asean

                tension_input = TensionInput(text=text)
                tension_result = classify_high_tension(tension_input)
                high_tension = tension_result.high_tension_event

                motivation_input = MotivationInput(text=text)
                motivation_result = classify_motivation(motivation_input)
                motivations = motivation_result.motivations

                # Combine evidence from tools
                evidence = []
                evidence.extend(geo_result.evidence)
                evidence.extend(tension_result.evidence)
                evidence.extend(motivation_result.evidence)

            except Exception as tool_error:
                self.logger.warning(f"Tool-based fallback failed: {tool_error}")
                affects_singapore = False
                affects_asean = False
                high_tension = False
                motivations = ["unknown"]
                evidence = []

            # Store results in state
            state.extracted["affects_singapore"] = affects_singapore
            state.extracted["affects_asean"] = affects_asean
            state.extracted["global_implications"] = global_implications
            state.extracted["primary_regions_affected"] = primary_regions_affected
            state.extracted["high_tension_event"] = high_tension
            state.extracted["tension_level"] = tension_level
            state.extracted["primary_motivation"] = primary_motivation
            state.extracted["secondary_motivations"] = secondary_motivations
            state.extracted["possible_motivations"] = [primary_motivation] + secondary_motivations  # Backward compatibility

            # Consolidate all geopolitical analysis into one object
            consolidated_geopolitical_analysis = geopolitical_analysis.copy() if geopolitical_analysis else {}

            # Add escalation risk and metadata to the geopolitical analysis object
            consolidated_geopolitical_analysis["escalation_risk"] = escalation_risk
            consolidated_geopolitical_analysis["analysis_metadata"] = {
                "confidence": confidence,
                "reasoning": reasoning,
                "method": "llm_enhanced"
            }

            state.extracted["geopolitical_analysis"] = consolidated_geopolitical_analysis

            # Extract specific geopolitical fields for final JSON output (for backward compatibility)
            state.extracted["underlying_causes"] = consolidated_geopolitical_analysis.get("underlying_causes", [])
            state.extracted["strategic_implications"] = consolidated_geopolitical_analysis.get("strategic_implications", [])
            state.extracted["regional_context"] = consolidated_geopolitical_analysis.get("regional_context", "")
            state.extracted["escalation_potential"] = consolidated_geopolitical_analysis.get("escalation_potential", "")
            state.extracted["stakeholder_interests"] = consolidated_geopolitical_analysis.get("stakeholder_interests", "")

            # Mark geographic analysis as attempted
            state.extracted["geographic_analysis_attempted"] = True

            state.evidence.extend(evidence)

            self.log_processing("Enhanced geo-motivation and geopolitical analysis complete", {
                "affects_singapore": affects_singapore,
                "affects_asean": affects_asean,
                "global_implications": global_implications,
                "regions_affected": len(primary_regions_affected),
                "high_tension": high_tension,
                "tension_level": tension_level,
                "escalation_risk": escalation_risk,
                "primary_motivation": primary_motivation,
                "secondary_motivations": len(secondary_motivations),
                "geopolitical_insights": bool(geopolitical_analysis),
                "confidence": confidence,
                "token_usage": self.token_usage
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in LLM geo/motivation analysis: {e}")
            # Fallback to tool-based analysis
            try:
                text = state.parsed.get("text", "") if state.parsed else ""

                geo_input = GeoInput(text=text)
                geo_result = classify_geo_scope(geo_input)
                state.extracted["affects_singapore"] = geo_result.affects_singapore
                state.extracted["affects_asean"] = geo_result.affects_asean

                tension_input = TensionInput(text=text)
                tension_result = classify_high_tension(tension_input)
                state.extracted["high_tension_event"] = tension_result.high_tension_event

                motivation_input = MotivationInput(text=text)
                motivation_result = classify_motivation(motivation_input)
                state.extracted["possible_motivations"] = motivation_result.motivations

                state.evidence.extend(geo_result.evidence)
                state.evidence.extend(tension_result.evidence)
                state.evidence.extend(motivation_result.evidence)
            except Exception as fallback_error:
                self.logger.error(f"Fallback geo/motivation analysis also failed: {fallback_error}")
                self._set_empty_geo_motivation(state)

            return state

    def _set_empty_geo_motivation(self, state: GraphState):
        """Set empty geo/motivation data in state."""
        state.extracted["affects_singapore"] = False
        state.extracted["affects_asean"] = False
        state.extracted["global_implications"] = False
        state.extracted["primary_regions_affected"] = []
        state.extracted["high_tension_event"] = False
        state.extracted["tension_level"] = "low"
        state.extracted["primary_motivation"] = "unknown"
        state.extracted["secondary_motivations"] = []
        state.extracted["possible_motivations"] = ["unknown"]  # Backward compatibility

        # Consolidated geopolitical analysis object with all related data
        state.extracted["geopolitical_analysis"] = {
            "underlying_causes": [],
            "strategic_implications": [],
            "regional_context": "",
            "escalation_potential": "",
            "stakeholder_interests": "",
            "escalation_risk": "low",
            "analysis_metadata": {
                "confidence": "low",
                "reasoning": "Analysis failed or no content available",
                "method": "fallback"
            }
        }

        # Set empty geopolitical fields for backward compatibility
        state.extracted["underlying_causes"] = []
        state.extracted["strategic_implications"] = []
        state.extracted["regional_context"] = ""
        state.extracted["escalation_potential"] = ""
        state.extracted["stakeholder_interests"] = ""

        # Mark geographic analysis as attempted (even if failed)
        state.extracted["geographic_analysis_attempted"] = True