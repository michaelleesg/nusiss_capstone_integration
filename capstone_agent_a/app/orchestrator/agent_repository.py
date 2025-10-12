"""Agent Repository - Single interface for orchestrator to access all agents."""

import logging
from typing import Optional

from ..state import GraphState
from .agents import (
    EntityAgent, IOCAgent, CVEAgent, MITREAgent,
    SummarizeAgent, GeoMotivationAgent, CyberAgent,
    ValidatorAgent, StoreAgent
)
from .agents.fetch_agent import FetchAgent
from .agents.detect_type_agent import DetectTypeAgent
from .agents.parse_agents import (
    MISPParseAgent, STIXParseAgent,
    HTMLParseAgent, PDFParseAgent, JSONParseAgent, TextParseAgent
)

logger = logging.getLogger(__name__)


class AgentRepository:
    """Repository pattern for agent management - provides clean interface for orchestrator."""

    def __init__(self):
        """Initialize agent repository with lazy loading."""
        # Lazy-loaded agents for CTI processing
        self._entity_agent: Optional[EntityAgent] = None
        self._ioc_agent: Optional[IOCAgent] = None
        self._cve_agent: Optional[CVEAgent] = None
        self._mitre_agent: Optional[MITREAgent] = None
        self._summarize_agent: Optional[SummarizeAgent] = None
        self._geo_agent: Optional[GeoMotivationAgent] = None
        self._cyber_agent: Optional[CyberAgent] = None
        self._validator_agent: Optional[ValidatorAgent] = None
        self._store_agent: Optional[StoreAgent] = None

        # Lazy-loaded agents for data handling
        self._fetch_agent: Optional[FetchAgent] = None
        self._detect_type_agent: Optional[DetectTypeAgent] = None
        self._misp_parse_agent: Optional[MISPParseAgent] = None
        self._stix_parse_agent: Optional[STIXParseAgent] = None
        self._html_parse_agent: Optional[HTMLParseAgent] = None
        self._pdf_parse_agent: Optional[PDFParseAgent] = None
        self._json_parse_agent: Optional[JSONParseAgent] = None
        self._text_parse_agent: Optional[TextParseAgent] = None

        logger.info("Agent repository initialized with lazy loading for all agents")

    def extract_entities(self, state: GraphState) -> GraphState:
        """Extract threat intelligence entities using EntityAgent."""
        if self._entity_agent is None:
            self._entity_agent = EntityAgent()
            logger.debug("EntityAgent instantiated")

        return self._entity_agent.process_with_token_tracking(state)

    def extract_iocs(self, state: GraphState) -> GraphState:
        """Extract IOCs using IOCAgent (includes LLM filtering)."""
        if self._ioc_agent is None:
            self._ioc_agent = IOCAgent()
            logger.debug("IOCAgent instantiated")

        return self._ioc_agent.process_with_token_tracking(state)

    def extract_cves(self, state: GraphState) -> GraphState:
        """Extract and enrich CVEs using CVEAgent."""
        if self._cve_agent is None:
            self._cve_agent = CVEAgent()
            logger.debug("CVEAgent instantiated")

        return self._cve_agent.process_with_token_tracking(state)

    def map_mitre_ttps(self, state: GraphState) -> GraphState:
        """Map MITRE ATT&CK tactics and techniques using MITREAgent."""
        if self._mitre_agent is None:
            self._mitre_agent = MITREAgent()
            logger.debug("MITREAgent instantiated")

        return self._mitre_agent.process_with_token_tracking(state)

    def generate_summary(self, state: GraphState) -> GraphState:
        """Generate threat intelligence summary using SummarizeAgent."""
        if self._summarize_agent is None:
            self._summarize_agent = SummarizeAgent()
            logger.debug("SummarizeAgent instantiated")

        return self._summarize_agent.process_with_token_tracking(state)

    def analyze_geographic_scope(self, state: GraphState) -> GraphState:
        """Analyze geographic scope and motivation using GeoMotivationAgent."""
        if self._geo_agent is None:
            self._geo_agent = GeoMotivationAgent()
            logger.debug("GeoMotivationAgent instantiated")

        return self._geo_agent.process_with_token_tracking(state)

    def classify_cyber_relevance(self, state: GraphState) -> GraphState:
        """Classify cyber-relevance using CyberAgent."""
        if self._cyber_agent is None:
            self._cyber_agent = CyberAgent()
            logger.debug("CyberAgent instantiated")

        return self._cyber_agent.process_with_token_tracking(state)

    def validate_and_complete(self, state: GraphState) -> GraphState:
        """Validate and complete data using ValidatorAgent."""
        if self._validator_agent is None:
            self._validator_agent = ValidatorAgent()
            logger.debug("ValidatorAgent instantiated")

        return self._validator_agent.process_with_token_tracking(state)

    def store_results(self, state: GraphState) -> GraphState:
        """Store final results using StoreAgent."""
        if self._store_agent is None:
            self._store_agent = StoreAgent()
            logger.debug("StoreAgent instantiated")

        return self._store_agent.process(state)

    def fetch_content(self, state: GraphState) -> GraphState:
        """Fetch URL content using FetchAgent."""
        if self._fetch_agent is None:
            self._fetch_agent = FetchAgent()
            logger.debug("FetchAgent instantiated")

        return self._fetch_agent.process(state)

    def detect_content_type(self, state: GraphState) -> GraphState:
        """Detect content type using DetectTypeAgent."""
        if self._detect_type_agent is None:
            self._detect_type_agent = DetectTypeAgent()
            logger.debug("DetectTypeAgent instantiated")

        return self._detect_type_agent.process(state)

    def parse_misp_content(self, state: GraphState) -> GraphState:
        """Parse MISP content using MISPParseAgent."""
        if self._misp_parse_agent is None:
            self._misp_parse_agent = MISPParseAgent()
            logger.debug("MISPParseAgent instantiated")

        return self._misp_parse_agent.process(state)

    def parse_stix_content(self, state: GraphState) -> GraphState:
        """Parse STIX content using STIXParseAgent."""
        if self._stix_parse_agent is None:
            self._stix_parse_agent = STIXParseAgent()
            logger.debug("STIXParseAgent instantiated")

        return self._stix_parse_agent.process(state)

    def extract_rss_urls(self, state: GraphState) -> GraphState:
        """Extract URLs from RSS feed for individual processing by orchestrator.

        This capability:
        1. Parses the RSS feed to extract individual items
        2. Extracts URLs from each item
        3. Stores URLs in state for orchestrator to process individually
        """
        import base64
        from ..tools.parsers.rss_parse import rss_parse, RSSParseInput

        try:
            logger.info("Extracting URLs from RSS feed")

            # Parse RSS content to get individual items
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            content_text = content_bytes.decode('utf-8', errors='ignore')

            parse_input = RSSParseInput(xml=content_text)
            parse_result = rss_parse(parse_input)

            if not parse_result.items:
                logger.warning("No items found in RSS feed")
                state.extracted["rss_urls_extracted"] = True
                state.extracted["rss_urls"] = []
                return state

            # Extract URLs from RSS items
            rss_urls = []
            for i, item in enumerate(parse_result.items):
                item_url = item.link
                if not item_url:
                    logger.warning(f"RSS item {i+1} missing link, skipping")
                    continue

                # Store URL with metadata for later processing
                rss_urls.append({
                    "url": item_url,
                    "metadata": {
                        "title": item.title,
                        "summary": item.summary,
                        "published": item.published,
                        "content": item.content,
                        "source_feed_title": parse_result.feed.get("title", ""),
                        "source_feed_url": state.url
                    }
                })

            logger.info(f"Extracted {len(rss_urls)} URLs from RSS feed")

            # Store URLs in state for orchestrator to process
            state.extracted["rss_urls_extracted"] = True
            state.extracted["rss_urls"] = rss_urls
            state.extracted["rss_feed_title"] = parse_result.feed.get("title", "")
            state.extracted["rss_feed_description"] = parse_result.feed.get("description", "")

            return state

        except Exception as e:
            logger.error(f"Error extracting RSS URLs: {e}")
            state.extracted["rss_urls_extracted"] = True
            state.extracted["rss_urls"] = []
            state.extracted["rss_extraction_error"] = str(e)
            return state

    def parse_html_content(self, state: GraphState) -> GraphState:
        """Parse HTML content using HTMLParseAgent."""
        if self._html_parse_agent is None:
            self._html_parse_agent = HTMLParseAgent()
            logger.debug("HTMLParseAgent instantiated")

        return self._html_parse_agent.process_with_token_tracking(state)

    def parse_pdf_content(self, state: GraphState) -> GraphState:
        """Parse PDF content using PDFParseAgent."""
        if self._pdf_parse_agent is None:
            self._pdf_parse_agent = PDFParseAgent()
            logger.debug("PDFParseAgent instantiated")

        return self._pdf_parse_agent.process(state)

    def parse_json_content(self, state: GraphState) -> GraphState:
        """Parse JSON content using JSONParseAgent."""
        if self._json_parse_agent is None:
            self._json_parse_agent = JSONParseAgent()
            logger.debug("JSONParseAgent instantiated")

        return self._json_parse_agent.process(state)

    def parse_text_content(self, state: GraphState) -> GraphState:
        """Parse plain text content using TextParseAgent."""
        if self._text_parse_agent is None:
            self._text_parse_agent = TextParseAgent()
            logger.debug("TextParseAgent instantiated")

        return self._text_parse_agent.process_with_token_tracking(state)

    def get_available_capabilities(self) -> list[str]:
        """Get list of available processing capabilities."""
        return [
            # Data handling capabilities
            "fetch_content",
            "detect_content_type",
            "parse_misp_content",
            "parse_stix_content",
            "extract_rss_urls",
            "parse_html_content",
            "parse_pdf_content",
            "parse_json_content",
            "parse_text_content",
            # CTI processing capabilities
            "extract_entities",
            "extract_iocs",
            "extract_cves",
            "map_mitre_ttps",
            "generate_summary",
            "analyze_geographic_scope",
            "classify_cyber_relevance",
            "validate_and_complete",
            "store_results"
        ]

    def get_capability_description(self, capability: str) -> str:
        """Get description of a specific capability."""
        descriptions = {
            # Data handling capabilities
            "fetch_content": "Fetch URL content and handle memory checking for duplicates",
            "detect_content_type": "Analyze MIME types and content samples to determine parsing approach",
            "parse_misp_content": "Parse MISP event JSON and extract structured threat intelligence data",
            "parse_stix_content": "Parse STIX 2.x bundles and extract objects and relationships",
            "extract_rss_urls": "Extract child URLs from RSS feed for individual processing",
            "parse_html_content": "Convert HTML pages to markdown for analysis",
            "parse_pdf_content": "Extract text content from PDF documents",
            "parse_json_content": "Normalize and structure generic JSON data",
            # CTI processing capabilities
            "extract_entities": "Extract threat actors, malware, victims, sectors, and products using LLM analysis",
            "extract_iocs": "Extract and filter IOCs (URLs, domains, IPs, hashes, files) using pattern matching + LLM filtering",
            "extract_cves": "Extract CVEs and enrich with CVSS scores, KEV status, and severity information",
            "map_mitre_ttps": "Map content to MITRE ATT&CK tactics, techniques, and subtechniques",
            "generate_summary": "Generate concise threat intelligence summary",
            "analyze_geographic_scope": "Analyze geographic scope, ASEAN/Singapore impact, and threat motivations",
            "classify_cyber_relevance": "Determine if content is cyber-security related",
            "validate_and_complete": "Validate extracted data and fill missing required fields",
            "store_results": "Store final CTI artifact to database and emit to output"
        }
        return descriptions.get(capability, "Unknown capability")

    def cleanup(self):
        """Clean up agent resources."""
        # Reset all CTI processing agents for garbage collection
        self._entity_agent = None
        self._ioc_agent = None
        self._cve_agent = None
        self._mitre_agent = None
        self._summarize_agent = None
        self._geo_agent = None
        self._cyber_agent = None
        self._validator_agent = None
        self._store_agent = None

        # Reset all data handling agents for garbage collection
        self._fetch_agent = None
        self._detect_type_agent = None
        self._misp_parse_agent = None
        self._stix_parse_agent = None
        self._html_parse_agent = None
        self._pdf_parse_agent = None
        self._json_parse_agent = None

        logger.info("Agent repository cleaned up")