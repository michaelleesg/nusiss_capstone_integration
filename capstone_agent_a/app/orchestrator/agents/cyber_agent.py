"""Cybersecurity relevance classification agent."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.nlp import is_cyber_related, CyberInput


class CyberAgent(BaseAgent):
    """Agent responsible for cybersecurity relevance classification."""

    def __init__(self):
        super().__init__("cyber")

    def get_system_prompt(self) -> str:
        return """You are a cybersecurity relevance classification agent.

Determine if content is cybersecurity-related by analyzing for:

CYBER SECURITY INDICATORS:
- Malware and threats (viruses, trojans, ransomware)
- Attack methods (phishing, DDoS, injection, etc.)
- Vulnerabilities and exploits (CVEs, zero-days)
- Security incidents and breaches
- Threat actors and campaigns
- IOCs (domains, IPs, hashes, URLs)
- Security tools and defenses
- Incident response and forensics

POSITIVE INDICATORS:
- Technical security content
- Threat intelligence reports
- Security advisories and alerts
- Malware analysis
- Attack attribution
- Defense strategies

NEGATIVE INDICATORS:
- General business news
- Non-security technology topics
- Marketing content
- Unrelated technical documentation

When in doubt, lean toward classifying as cyber-related to avoid missing potential threats."""

    def process(self, state: GraphState) -> GraphState:
        """Classify cybersecurity relevance using summary and metadata."""
        try:
            # Build classification input from extracted data (summary + metadata)
            classification_parts = []

            # Add title if available
            if state.extracted and state.extracted.get("title"):
                classification_parts.append(f"Title: {state.extracted['title']}")

            # Add summary if available (preferred - already concentrated cyber content)
            if state.extracted and state.extracted.get("summary"):
                classification_parts.append(f"Summary: {state.extracted['summary']}")

            # Add CVEs (strong cyber indicator)
            if state.extracted and state.extracted.get("cve_vulns"):
                cves = state.extracted["cve_vulns"][:5]  # First 5 CVEs
                if cves:
                    classification_parts.append(f"CVEs mentioned: {', '.join(cves)}")

            # Add IOC counts (strong cyber indicator)
            if state.extracted and state.extracted.get("iocs"):
                iocs = state.extracted["iocs"]
                ioc_counts = []
                if iocs.get("urls"):
                    ioc_counts.append(f"{len(iocs['urls'])} URLs")
                if iocs.get("domains"):
                    ioc_counts.append(f"{len(iocs['domains'])} domains")
                if iocs.get("hashes"):
                    ioc_counts.append(f"{len(iocs['hashes'])} hashes")
                if iocs.get("ips"):
                    ioc_counts.append(f"{len(iocs['ips'])} IPs")
                if ioc_counts:
                    classification_parts.append(f"IOCs found: {', '.join(ioc_counts)}")

            # Add MITRE TTPs (strong cyber indicator)
            if state.extracted and state.extracted.get("mitre_ttps"):
                ttps = state.extracted["mitre_ttps"][:3]  # First 3 TTPs
                if ttps:
                    classification_parts.append(f"MITRE TTPs: {', '.join(ttps)}")

            # Use extracted metadata if available, otherwise fallback to parsed text
            if classification_parts:
                text = "\n\n".join(classification_parts)
                self.logger.info(f"Using extracted metadata for cyber classification ({len(text)} chars, ~{len(text)//4} tokens)")
            else:
                # Fallback: use parsed text (truncated)
                text = state.parsed.get("text", "") if state.parsed else ""
                if not text.strip():
                    self.logger.warning("No content available for cyber classification")
                    state.extracted["cyber_related"] = True  # Default to True when uncertain
                    state.extracted["cyber_classification_attempted"] = True
                    return state

                # Truncate if too long (reduced from 10000 to 5000)
                max_chars = 5000
                if len(text) > max_chars:
                    text = text[:max_chars] + "... [truncated for analysis]"
                self.logger.info(f"Using truncated full text for cyber classification ({len(text)} chars)")

            # Create user prompt with the content
            user_input = f"""
Analyze the following content to determine if it is cybersecurity-related:

Content:
{text}
"""

            # Use LLM to classify with the system prompt
            llm_response = self.call_llm(self.get_system_prompt(), user_input)

            # Parse LLM response with simple text analysis - look for key indicators
            response_lower = llm_response.lower()

            # Look for clear cyber-related indicators in the LLM response
            if any(keyword in response_lower for keyword in [
                "cyber", "security", "threat", "malware", "attack", "vulnerability",
                "apt", "espionage", "breach", "incident", "compromise"
            ]):
                cyber_related = True
            elif any(phrase in response_lower for phrase in [
                "not cyber", "not security", "not related", "non-security",
                "not threat", "not malicious", "no cyber"
            ]):
                cyber_related = False
            else:
                # If LLM response is unclear, fall back to keyword analysis
                text_lower = text.lower()
                cyber_keywords = ["cyber", "malware", "threat", "attack", "apt", "security", "breach"]
                cyber_score = sum(1 for keyword in cyber_keywords if keyword in text_lower)
                cyber_related = cyber_score > 0

            state.extracted["cyber_related"] = cyber_related
            # Mark that cyber classification was attempted so orchestrator doesn't loop
            state.extracted["cyber_classification_attempted"] = True

            self.log_processing("Cybersecurity classification complete using LLM", {
                "cyber_related": cyber_related,
                "token_usage": self.token_usage
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in LLM cyber classification: {e}")
            # Fallback to tool-based classification
            try:
                text = state.parsed.get("text", "") if state.parsed else ""
                cyber_input = CyberInput(text=text)
                cyber_result = is_cyber_related(cyber_input)
                state.extracted["cyber_related"] = cyber_result.cyber_related
            except Exception as fallback_error:
                self.logger.error(f"Fallback cyber classification also failed: {fallback_error}")
                # Default to True on error to avoid missing potential threats
                state.extracted["cyber_related"] = True

            # Mark that cyber classification was attempted so orchestrator doesn't loop
            state.extracted["cyber_classification_attempted"] = True

            return state