"""Threat intelligence summarization agent."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.nlp import summarize_threat, SummarizeInput


class SummarizeAgent(BaseAgent):
    """Agent responsible for generating threat intelligence summaries."""

    def __init__(self):
        super().__init__("summarize")

    def get_system_prompt(self) -> str:
        return """You are a threat intelligence summarization agent.

Your task is to generate concise, informative summaries of CTI content that focus on:
- Key threats and threat actors
- Vulnerabilities and exploits
- Indicators of compromise
- Impact and affected systems
- Recommended actions

Generate comprehensive summaries of 3-5 sentences that capture essential threat intelligence information including context, methods, impact, and recommendations.

Also extract a meaningful title from the document content if no title is provided.

CRITICAL DETECTION REQUIREMENTS:
1. **Zero-Day Detection**: Determine if this article mentions NEW/CURRENT zero-day vulnerabilities (not historical ones that are now patched). Look for:
   - "zero-day", "0-day", "zero day"
   - "unknown vulnerability", "undisclosed vulnerability"
   - "no patch available", "unpatched vulnerability"
   - Vulnerabilities being exploited BEFORE patches exist
   - CVEs described as zero-day or exploited in the wild before disclosure

2. **Active Exploitation Detection**: Determine if vulnerabilities mentioned are currently being exploited:
   - "actively exploited", "exploitation in the wild", "attacks observed"
   - "threat actors are using", "campaigns targeting"
   - Present-tense exploitation activities (not historical mentions)
   - Current attack campaigns or ongoing exploitation

IMPORTANT: Focus on CURRENT threats in this article, not historical references or patched vulnerabilities.

3. **Recommendations and Mitigations Extraction**: Extract any recommendations, mitigations, or defensive actions mentioned in the content:
   - Explicit recommendations: "update to version X", "apply patch", "disable feature"
   - Mitigation advice: "block IPs", "monitor for IOCs", "implement MFA", "review logs"
   - Defensive actions: "patch immediately", "update systems", "enable automatic updates"
   - Security best practices mentioned in context
   - If no explicit recommendations are present in the content, return empty string
   - Do NOT invent or suggest recommendations not mentioned in the original content

Output VALID JSON with title, summary, zero_day_mention, active_exploitation_mentioned, recommendations_and_mitigations, and evidence fields:
{
  "title": "Extracted document title (if no title provided) or use provided title",
  "summary": "Concise threat intelligence summary",
  "zero_day_mention": true/false,
  "active_exploitation_mentioned": true/false,
  "recommendations_and_mitigations": "Recommended actions, patches, mitigations, or defensive measures mentioned in the content (empty string if none)",
  "evidence": ["key evidence snippets from the content"]
}"""

    def process(self, state: GraphState) -> GraphState:
        """Generate threat intelligence summary using LLM-guided analysis."""
        try:
            if not state.parsed:
                raise ValueError("No parsed content available")

            # Prepare input data for LLM analysis
            content_type = state.parsed.get("type", "TEXT")
            title = state.parsed.get("title", "")
            text = state.parsed.get("text", "")

            # Use intelligent text processing for LLM input
            from .text_processor import prepare_llm_input
            text_data = prepare_llm_input(text, agent_type="summarize")

            # Create user prompt with the intelligently processed content
            user_input = f"""
Content Type: {content_type}
Title: {title if title else "No title provided"}
URL: {state.url}

Processing Strategy: {text_data['processing_strategy']}
Original Content Length: {text_data['original_tokens']} tokens
Processed Content Length: {text_data['processed_tokens']} tokens

Content to summarize:
{text_data['text']}
"""

            # Use LLM to generate summary with the system prompt
            llm_response = self.call_llm(self.get_system_prompt(), user_input)

            # Parse LLM response as JSON
            try:
                import json
                # Extract JSON from response if wrapped in markdown
                if "```json" in llm_response:
                    json_start = llm_response.find("```json") + 7
                    json_end = llm_response.find("```", json_start)
                    json_text = llm_response[json_start:json_end].strip()
                elif llm_response.strip().startswith("{"):
                    json_text = llm_response.strip()
                else:
                    # Try to find JSON in the response
                    json_start = llm_response.find("{")
                    json_end = llm_response.rfind("}") + 1
                    if json_start != -1 and json_end > json_start:
                        json_text = llm_response[json_start:json_end]
                    else:
                        raise ValueError("No valid JSON found in LLM response")

                llm_result = json.loads(json_text)

                # Extract title, summary, zero_day_mention, active_exploitation_mentioned, recommendations, and evidence from LLM response
                extracted_title = llm_result.get("title", "")
                summary = llm_result.get("summary", "Summary generation failed")
                zero_day_mention = llm_result.get("zero_day_mention", False)
                active_exploitation_mentioned = llm_result.get("active_exploitation_mentioned", False)
                recommendations = llm_result.get("recommendations_and_mitigations", "")
                evidence = llm_result.get("evidence", [])

                # Ensure evidence is in the correct format
                if isinstance(evidence, list):
                    formatted_evidence = []
                    for ev in evidence:
                        if isinstance(ev, str):
                            formatted_evidence.append({"loc": "body", "text": ev})
                        elif isinstance(ev, dict) and "text" in ev:
                            formatted_evidence.append(ev)
                    evidence = formatted_evidence
                elif isinstance(evidence, str):
                    # If evidence is a string, wrap it in proper structure
                    evidence = [{"loc": "body", "text": evidence}]
                else:
                    # If evidence is neither list nor string, use default
                    evidence = [{"loc": "body", "text": text[:200] + "..." if len(text) > 200 else text}]

            except (json.JSONDecodeError, ValueError) as e:
                self.logger.warning(f"Could not parse LLM JSON response: {e}, using fallback")
                # Fallback: use the LLM response as summary
                summary = llm_response[:500] + "..." if len(llm_response) > 500 else llm_response
                evidence = [{"loc": "body", "text": text[:200] + "..." if len(text) > 200 else text}]
                extracted_title = ""  # No title extracted in fallback case
                zero_day_mention = False  # Default to false in fallback
                active_exploitation_mentioned = False  # Default to false in fallback
                recommendations = ""  # Default to empty string in fallback

            # Store results
            state.extracted["summary"] = summary
            # Use extracted title from LLM if original title is missing, otherwise fall back to URL
            state.extracted["title"] = title if title else (extracted_title if extracted_title else state.url)
            # Store new detection fields
            state.extracted["zero_day_mention"] = zero_day_mention
            state.extracted["active_exploitation_mentioned"] = active_exploitation_mentioned
            state.extracted["recommendations_and_mitigations"] = recommendations

            # Safety check for evidence format
            if isinstance(evidence, str):
                evidence = [{"loc": "body", "text": evidence}]
            elif not isinstance(evidence, list):
                evidence = [{"loc": "body", "text": str(evidence)}]

            state.evidence.extend(evidence)

            self.log_processing("Summary generated using LLM", {
                "summary_chars": len(summary),
                "evidence_count": len(evidence),
                "token_usage": self.token_usage
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in LLM summarization: {e}")
            # Fallback to tool-based summarization
            try:
                summarize_input = SummarizeInput(
                    type=state.parsed.get("type", "TEXT"),
                    title=state.parsed.get("title"),
                    text=state.parsed.get("text", "")
                )
                summary_result = summarize_threat(summarize_input)
                state.extracted["summary"] = summary_result.summary
                state.extracted["title"] = state.parsed.get("title", state.url)
                state.extracted["zero_day_mention"] = False  # Tool-based fallback can't detect these
                state.extracted["active_exploitation_mentioned"] = False  # Tool-based fallback can't detect these
                state.extracted["recommendations_and_mitigations"] = ""  # Tool-based fallback can't extract these
                state.evidence.extend(summary_result.evidence)
            except Exception as fallback_error:
                self.logger.error(f"Fallback summarization also failed: {fallback_error}")
                state.extracted["summary"] = "Summary generation failed"
                state.extracted["title"] = state.url
                state.extracted["zero_day_mention"] = False  # Default when all methods fail
                state.extracted["active_exploitation_mentioned"] = False  # Default when all methods fail
                state.extracted["recommendations_and_mitigations"] = ""  # Default when all methods fail

            return state