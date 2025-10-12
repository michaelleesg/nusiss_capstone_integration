"""Enhanced MITRE ATT&CK technique mapping agent with multi-step approach."""

from .base_agent import BaseAgent
from ...state import GraphState
import json
import re
import logging


class MITREAgent(BaseAgent):
    """Enhanced MITRE agent using 3-step focused approach for better accuracy."""

    def __init__(self):
        super().__init__("mitre")

    def get_system_prompt(self) -> str:
        """System prompt for compatibility with base class."""
        return "Enhanced MITRE agent using 3-step approach for accurate technique identification."

    def get_behavior_analysis_prompt(self) -> str:
        """Step 1: Analyze content for attack behaviors and patterns."""
        return """You are a cybersecurity analyst specializing in attack behavior identification.

OBJECTIVE: Analyze threat intelligence content to identify specific attack behaviors, patterns, and methodologies described in the text.

FOCUS AREAS:
1. ATTACK VECTORS: How attackers gain initial access
2. EXECUTION METHODS: What tools/techniques used post-compromise
3. PERSISTENCE MECHANISMS: How attackers maintain access
4. EVASION TACTICS: Methods to avoid detection
5. DATA OPERATIONS: How data is accessed, collected, or exfiltrated
6. INFRASTRUCTURE: Command & control, communication methods
7. IMPACT ACTIVITIES: Damage, disruption, or final objectives

BEHAVIORAL PATTERNS TO IDENTIFY:
- Email-based attacks (phishing, malicious attachments)
- Web application exploitation (SQLi, XSS, RCE)
- System compromise methods (privilege escalation, lateral movement)
- Credential access attempts (dumping, brute force, theft)
- Stealth techniques (process injection, obfuscation, masquerading)
- Network activities (scanning, tunneling, exfiltration)
- File operations (encryption, deletion, modification)
- Registry/system modifications
- Tool usage (legitimate tools used maliciously)

ANALYSIS GUIDELINES:
- Focus on ACTIONS and METHODS described
- Look for HOW attacks are carried out
- Identify SPECIFIC TECHNIQUES mentioned
- Note SEQUENCE of attack activities
- Extract TECHNICAL DETAILS of implementation

OUTPUT FORMAT:
{
  "attack_behaviors": [
    {
      "behavior": "Brief description of attack behavior",
      "category": "initial_access|execution|persistence|defense_evasion|credential_access|discovery|lateral_movement|collection|command_control|exfiltration|impact",
      "description": "Detailed description with context",
      "evidence": "Specific text evidence supporting this behavior",
      "confidence": "high|medium|low"
    }
  ],
  "attack_sequence": ["ordered list of behaviors if sequence is clear"],
  "technical_details": {
    "tools_mentioned": ["specific tools identified"],
    "file_types": ["file types involved"],
    "protocols": ["network protocols mentioned"],
    "platforms": ["target platforms/systems"]
  }
}

Be specific and evidence-based. Only identify behaviors with clear supporting evidence in the content."""

    def get_technique_identification_prompt(self) -> str:
        """Step 2: Map behaviors to MITRE techniques AND extract explicit mentions."""
        return """You are a MITRE ATT&CK framework expert specializing in technique identification and mapping.

OBJECTIVE: Map identified attack behaviors to specific MITRE ATT&CK techniques AND extract any explicitly mentioned technique IDs with contextual validation.

PART A: BEHAVIORAL MAPPING
Map provided attack behaviors to specific MITRE techniques using these guidelines:

KEY TECHNIQUE MAPPINGS:
- Email phishing → T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link)
- Malicious documents/macros → T1059.005 (Visual Basic) + T1204.002 (Malicious File)
- PowerShell usage → T1059.001 (PowerShell)
- Command shell usage → T1059.003 (Windows Command Shell)
- Process injection → T1055 (Process Injection)
- Registry modifications → T1112 (Modify Registry), T1547.001 (Registry Run Keys)
- Credential dumping → T1003.001 (LSASS Memory), T1003.002 (Security Account Manager)
- Network scanning → T1018 (Remote System Discovery), T1016 (System Network Configuration Discovery)
- File encryption → T1486 (Data Encrypted for Impact)
- Web shell deployment → T1505.003 (Web Shell)
- Scheduled tasks → T1053.005 (Scheduled Task/Job)
- DLL hijacking → T1574.002 (DLL Side-Loading)
- Living-off-the-land → T1218 (System Binary Proxy Execution)
- C2 communications → T1071.001 (Web Protocols), T1102 (Web Service)
- Data exfiltration → T1041 (Exfiltration Over C2 Channel), T1567.002 (Exfiltration to Cloud Storage)

PART B: EXPLICIT TECHNIQUE EXTRACTION
Find explicitly mentioned MITRE technique IDs with validation:

VALID CONTEXTS (extract with high confidence):
- "MITRE ATT&CK T1566.001"
- "technique T1055"
- "uses T1027 for obfuscation"
- "T1059.001 PowerShell execution"
- "ATT&CK technique T1210"
- "MITRE T1566"

INVALID CONTEXTS (ignore these patterns):
- CVE references: "CVE-2023-1234"
- Version numbers: "T1000 Terminator", "AT&T"
- Technical specs: "T1 connection", "T1 timeout"
- File paths: "/tmp/T1234.txt", "log_T1055.dat"
- Product names: "Model T1566", "Intel T1200"
- Random alphanumeric: "UUID-T1234-abcd"

VALIDATION RULES:
1. Look for T#### or T####.### patterns
2. Require cybersecurity context within 50 characters
3. Keywords indicating valid context: "MITRE", "ATT&CK", "technique", "tactic", "uses", "employs"
4. Validate against standard MITRE technique format

OUTPUT FORMAT:
{
  "behavioral_techniques": [
    {
      "technique_id": "T####",
      "behavior_mapped": "specific behavior this maps to",
      "confidence": "high|medium|low",
      "evidence": "evidence from behaviors",
      "kill_chain_phase": "initial_access|execution|persistence|etc"
    }
  ],
  "explicit_techniques": [
    {
      "technique_id": "T####",
      "context": "surrounding text showing valid context",
      "confidence": "high|medium|low",
      "validation_keywords": ["keywords that validated this"]
    }
  ],
  "mapping_reasoning": "explanation of mapping logic"
}

Be conservative - only map techniques with strong evidence."""

    def get_validation_prompt(self) -> str:
        """Step 3: Validate and deduplicate final technique list."""
        return """You are a MITRE ATT&CK validation specialist ensuring accuracy and eliminating false positives.

OBJECTIVE: Validate identified techniques against original content, deduplicate, and provide final verified technique list.

VALIDATION CRITERIA:
1. EVIDENCE VERIFICATION: Each technique must have clear supporting evidence in original content
2. CONTEXT VALIDATION: Techniques must be applicable to the described attack scenario
3. LOGICAL CONSISTENCY: Techniques should form a coherent attack chain
4. CONFIDENCE ASSESSMENT: High confidence requires explicit mention or clear behavioral evidence

DEDUPLICATION RULES:
- Remove duplicate technique IDs
- When same technique found via multiple methods, keep highest confidence
- Merge evidence from behavioral and explicit sources
- Resolve conflicts by prioritizing explicit mentions

QUALITY CHECKS:
- Verify technique IDs are valid MITRE format (T#### or T####.###)
- Ensure techniques are contextually appropriate
- Remove techniques with insufficient evidence
- Flag potential false positives for review

OUTPUT FORMAT:
{
  "final_techniques": ["T1566.001", "T1059.001", ...],
  "technique_details": [
    {
      "technique_id": "T####",
      "confidence": "high|medium|low",
      "source": "behavioral|explicit|both",
      "evidence": "consolidated evidence supporting this technique",
      "kill_chain_phase": "phase in attack sequence"
    }
  ],
  "validation_summary": {
    "total_techniques": 5,
    "high_confidence": 3,
    "medium_confidence": 2,
    "low_confidence": 0,
    "deduplication_actions": "what was deduplicated",
    "false_positives_removed": ["list of removed techniques with reasons"]
  },
  "attack_pattern_analysis": "brief analysis of overall attack pattern and technique relationships"
}

Be thorough but conservative - accuracy is more important than completeness."""

    def analyze_attack_behaviors(self, text: str, context: dict) -> dict:
        """Step 1: Analyze content for attack behaviors."""
        try:
            user_input = f"""
Analyze this threat intelligence content to identify specific attack behaviors and patterns.

INTELLIGENCE CONTEXT:
{self._format_context(context)}

CONTENT TO ANALYZE:
{text}

Identify attack behaviors with supporting evidence. Focus on HOW attacks are carried out and WHAT techniques are described.
"""

            response = self.call_llm(self.get_behavior_analysis_prompt(), user_input)
            return self._parse_json_response(response, "behavior_analysis")

        except Exception as e:
            self.logger.error(f"Error in behavior analysis: {e}")
            return {"attack_behaviors": [], "attack_sequence": [], "technical_details": {}}

    def identify_techniques(self, behaviors: dict, text: str) -> dict:
        """Step 2: Map behaviors to techniques and extract explicit mentions."""
        try:
            user_input = f"""
Perform technique identification using two methods:

PART A: Map these identified attack behaviors to MITRE ATT&CK techniques:
{json.dumps(behaviors.get('attack_behaviors', []), indent=2)}

PART B: Extract explicitly mentioned technique IDs from this content:
{text[:3000]}

Provide comprehensive technique mapping with evidence and validation.
"""

            response = self.call_llm(self.get_technique_identification_prompt(), user_input)
            return self._parse_json_response(response, "technique_identification")

        except Exception as e:
            self.logger.error(f"Error in technique identification: {e}")
            return {"behavioral_techniques": [], "explicit_techniques": [], "mapping_reasoning": ""}

    def validate_and_deduplicate(self, mapped_techniques: dict, original_text: str) -> dict:
        """Step 3: Validate and deduplicate final technique list."""
        try:
            user_input = f"""
Validate and deduplicate these identified MITRE techniques:

BEHAVIORAL TECHNIQUES:
{json.dumps(mapped_techniques.get('behavioral_techniques', []), indent=2)}

EXPLICIT TECHNIQUES:
{json.dumps(mapped_techniques.get('explicit_techniques', []), indent=2)}

ORIGINAL CONTENT FOR VALIDATION:
{original_text[:2000]}

Provide final validated and deduplicated technique list with quality assessment.
"""

            response = self.call_llm(self.get_validation_prompt(), user_input)
            return self._parse_json_response(response, "validation")

        except Exception as e:
            self.logger.error(f"Error in validation: {e}")
            return {"final_techniques": [], "technique_details": [], "validation_summary": {}}

    def _format_context(self, context: dict) -> str:
        """Format intelligence context for prompts."""
        context_parts = []

        if context.get('actors'):
            context_parts.append(f"Threat Actors: {', '.join(context['actors'])}")
        if context.get('malware'):
            context_parts.append(f"Malware: {', '.join(context['malware'])}")
        if context.get('iocs'):
            ioc_summary = []
            for ioc_type, iocs in context['iocs'].items():
                if iocs:
                    ioc_summary.append(f"{ioc_type}: {len(iocs)}")
            if ioc_summary:
                context_parts.append(f"IOCs: {', '.join(ioc_summary)}")
        if context.get('cves'):
            context_parts.append(f"CVEs: {', '.join(context['cves'])}")

        return "\n".join(context_parts) if context_parts else "No specific intelligence context available."

    def _parse_json_response(self, response: str, step_name: str) -> dict:
        """Parse JSON response with fallback handling."""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'```json\s*\n(.*?)\n```', response, re.DOTALL)
            if not json_match:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)

            if json_match:
                json_text = json_match.group(1) if json_match.group(0).startswith('```') else json_match.group(0)
                return json.loads(json_text)
            else:
                self.logger.warning(f"No JSON found in {step_name} response")
                return {}

        except (json.JSONDecodeError, ValueError) as e:
            self.logger.warning(f"Failed to parse JSON in {step_name}: {e}")
            return {}

    def process(self, state: GraphState) -> GraphState:
        """Process using enhanced 3-step MITRE technique mapping."""
        try:
            text = state.parsed.get("text", "") if state.parsed else ""
            summary = state.extracted.get("summary", "")

            if not text.strip() and not summary.strip():
                self.logger.warning("No text content available for MITRE mapping")
                state.extracted["mitre_ttps"] = []
                state.extracted["mitre_ttps_extraction_attempted"] = True
                return state

            # Use intelligent text processing
            from .text_processor import prepare_llm_input
            content_for_analysis = f"{summary}\n\n{text}" if summary else text
            text_data = prepare_llm_input(content_for_analysis, agent_type="mitre")

            # Prepare intelligence context
            context = {
                'actors': state.extracted.get("threat_actors", []),
                'malware': state.extracted.get("malware", []),
                'iocs': state.extracted.get("iocs", {}),
                'cves': state.extracted.get("cve_vulns", []),
                'sectors': state.extracted.get("sectors", []),
                'victims': state.extracted.get("victims", [])
            }

            self.logger.info("Starting enhanced 3-step MITRE analysis")

            # Step 1: Analyze attack behaviors
            self.logger.info("Step 1: Analyzing attack behaviors")
            behaviors = self.analyze_attack_behaviors(text_data['text'], context)

            # Step 2: Identify techniques (behavioral + explicit)
            self.logger.info("Step 2: Identifying MITRE techniques")
            techniques = self.identify_techniques(behaviors, text_data['text'])

            # Step 3: Validate and deduplicate
            self.logger.info("Step 3: Validating and deduplicating techniques")
            final_results = self.validate_and_deduplicate(techniques, text_data['text'])

            # Extract final technique list
            final_techniques = final_results.get('final_techniques', [])
            technique_details = final_results.get('technique_details', [])

            # Prepare evidence for state
            evidence = []
            for detail in technique_details:
                evidence.append({
                    "loc": "body",
                    "text": f"[{detail.get('technique_id', '')}|{detail.get('confidence', 'medium')}|{detail.get('source', 'unknown')}] {detail.get('evidence', '')}"[:400],
                    "technique": detail.get('technique_id', ''),
                    "confidence": detail.get('confidence', 'medium'),
                    "source": detail.get('source', 'unknown')
                })

            # Store results
            state.extracted["mitre_ttps"] = final_techniques
            state.extracted["mitre_ttps_extraction_attempted"] = True
            state.evidence.extend(evidence)

            # Store detailed analysis
            state.extracted["mitre_analysis"] = {
                "method": "enhanced_3step",
                "confidence": final_results.get('validation_summary', {}).get('total_techniques', 0),
                "step1_behaviors": len(behaviors.get('attack_behaviors', [])),
                "step2_behavioral": len(techniques.get('behavioral_techniques', [])),
                "step2_explicit": len(techniques.get('explicit_techniques', [])),
                "step3_final": len(final_techniques),
                "validation_summary": final_results.get('validation_summary', {}),
                "attack_pattern": final_results.get('attack_pattern_analysis', ''),
                "processing_strategy": text_data.get('processing_strategy', 'unknown')
            }

            self.log_processing("Enhanced 3-step MITRE analysis complete", {
                "final_techniques": len(final_techniques),
                "evidence_items": len(evidence),
                "step1_behaviors": len(behaviors.get('attack_behaviors', [])),
                "step2_total": len(techniques.get('behavioral_techniques', [])) + len(techniques.get('explicit_techniques', [])),
                "validation_removed": len(final_results.get('validation_summary', {}).get('false_positives_removed', [])),
                "token_usage": self.token_usage
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in enhanced MITRE analysis: {e}")
            state.extracted["mitre_ttps"] = []
            state.extracted["mitre_ttps_extraction_attempted"] = True
            state.extracted["mitre_analysis"] = {
                "method": "enhanced_3step_failed",
                "error": str(e),
                "confidence": "low"
            }
            return state