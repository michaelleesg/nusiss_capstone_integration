"""CVE extraction and enrichment tools."""

import json
import logging
import os
import re
import time
from typing import Dict, List, Optional, Set

import httpx
import nvdlib
from pydantic import BaseModel, Field

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configuration
NVD_API_KEY = os.getenv("NVD_API_KEY")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY", "1.0"))


class StructuredCVE(BaseModel):
    """CVE with confidence and source information."""
    value: str = Field(description="CVE identifier")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    source: str = Field(description="Source/provenance of the CVE")
    severity: Optional[str] = Field(default=None, description="CVE severity if known")
    cvss_score: Optional[float] = Field(default=None, description="CVSS score if known")
    kev_listed: bool = Field(default=False, description="Is in CISA KEV list")
    relevance_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Context relevance score 0-1")
    relevance_category: str = Field(default="primary", description="primary/related/contextual/reference")
    relevance_reasoning: str = Field(default="", description="Explanation for relevance assessment")

from ..dedup import normalize_cve

logger = logging.getLogger(__name__)

# Simple in-memory cache for NVD data to reduce API calls
_nvd_cache = {}


class CVEExtractInput(BaseModel):
    """Input for CVE extraction."""

    text: str = Field(description="Text to extract CVEs from")


class CVEExtractOutput(BaseModel):
    """Output for CVE extraction."""

    cves: List[StructuredCVE] = Field(description="Extracted CVE identifiers with confidence")


class CVEEnrichInput(BaseModel):
    """Input for CVE enrichment."""

    cves: List[str] = Field(description="CVE identifiers to enrich")
    prefer_offline_cache: bool = Field(default=True, description="Prefer offline cache over API")


class CVEEnrichOutput(BaseModel):
    """Output for CVE enrichment."""

    enriched_cves: List[StructuredCVE] = Field(description="Enriched CVE data")
    severity: Dict[str, str] = Field(description="CVE severity ratings")
    cvss_score: Dict[str, float] = Field(description="CVSS base scores")
    patch_available: Dict[str, bool] = Field(description="Patch availability")
    products: Dict[str, List[str]] = Field(description="Affected products")
    cpe_strings: Dict[str, List[str]] = Field(description="CPE strings (non-deprecated)")
    affected_versions: Dict[str, List[Dict]] = Field(description="Affected versions with ranges")
    active_exploitation: Dict[str, bool] = Field(description="Active exploitation status")


def extract_cves_from_text(text: str) -> Set[str]:
    """Extract CVE identifiers from text."""
    cves = set()

    # Single comprehensive pattern that matches valid CVE format
    # CVE-YYYY-NNNN where YYYY >= 1999 and NNNN >= 4 digits
    cve_pattern = r'\b(?:CVE[-\s]*)?(?P<year>199[9]|20\d{2}|2[1-9]\d{2})[-\s]+(?P<number>\d{4,})\b'

    matches = re.finditer(cve_pattern, text, re.IGNORECASE)
    for match in matches:
        year = match.group('year')
        number = match.group('number')

        # Ensure it's a valid CVE (not part of a longer string like STIX ID)
        full_match = match.group(0)
        start_pos = match.start()
        end_pos = match.end()

        # Check context to avoid STIX IDs and other UUIDs
        # STIX IDs have format: type--uuid where uuid contains multiple dashes
        if start_pos > 0:
            char_before = text[start_pos - 1]
            # Skip if preceded by alphanumeric or dash (likely part of UUID)
            if char_before.isalnum() or char_before == '-':
                continue

        if end_pos < len(text):
            char_after = text[end_pos]
            # Skip if followed by dash and more hex chars (likely UUID)
            if char_after == '-' and end_pos + 1 < len(text):
                remaining = text[end_pos + 1:end_pos + 10]
                if re.match(r'[0-9a-f]{4,}', remaining, re.IGNORECASE):
                    continue

        # Construct normalized CVE
        cve = f"CVE-{year}-{number}"
        normalized_cve = normalize_cve(cve)

        # Final validation
        if re.match(r'CVE-(199[9]|20\d{2}|2[1-9]\d{2})-\d{4,}$', normalized_cve):
            cves.add(normalized_cve)

    return cves


def load_kev_cache() -> Set[str]:
    """Load Known Exploited Vulnerabilities cache."""
    try:
        # Try to load from local cache first
        import os
        cache_file = "./data/kev_cache.json"

        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                kev_data = json.load(f)
                if isinstance(kev_data, dict) and "vulnerabilities" in kev_data:
                    return {normalize_cve(vuln.get("cveID", ""))
                           for vuln in kev_data["vulnerabilities"]
                           if vuln.get("cveID")}

        # Fallback: fetch from CISA
        logger.info("Fetching KEV data from CISA...")
        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        with httpx.Client(timeout=30) as client:
            response = client.get(kev_url)
            response.raise_for_status()
            kev_data = response.json()

            # Cache the data
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            with open(cache_file, 'w') as f:
                json.dump(kev_data, f)

            if isinstance(kev_data, dict) and "vulnerabilities" in kev_data:
                return {normalize_cve(vuln.get("cveID", ""))
                       for vuln in kev_data["vulnerabilities"]
                       if vuln.get("cveID")}

    except Exception as e:
        logger.warning(f"Failed to load KEV cache: {e}")

    return set()


def enrich_cve_with_nvd(cve: str) -> Dict[str, any]:
    """Enrich CVE using NVD data with retry mechanism and API key."""
    try:
        # Check cache first
        if cve in _nvd_cache:
            logger.info(f"Using cached NVD data for {cve}")
            return _nvd_cache[cve]

        logger.info(f"Fetching NVD data for {cve}")

        # Search for the CVE in NVD with retry mechanism
        results = None
        last_error = None

        for attempt in range(MAX_RETRIES):
            try:
                # Use NVD API key if available
                if NVD_API_KEY:
                    logger.debug(f"Using NVD API key for {cve} (attempt {attempt + 1}/{MAX_RETRIES})")
                    results = nvdlib.searchCVE(cveId=cve, key=NVD_API_KEY)
                else:
                    logger.debug(f"No NVD API key, using unauthenticated access for {cve} (attempt {attempt + 1}/{MAX_RETRIES})")
                    results = nvdlib.searchCVE(cveId=cve)
                break  # Success, exit retry loop

            except Exception as api_error:
                last_error = api_error
                logger.warning(f"NVD API error for {cve} (attempt {attempt + 1}/{MAX_RETRIES}): {api_error}")

                if attempt < MAX_RETRIES - 1:
                    logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                    time.sleep(RETRY_DELAY)
                else:
                    logger.error(f"All {MAX_RETRIES} attempts failed for {cve}")

        # If all retries failed, return unknown data
        if results is None:
            logger.error(f"Failed to fetch NVD data for {cve} after {MAX_RETRIES} attempts. Last error: {last_error}")
            return {
                "severity": "UNKNOWN",
                "cvss_score": 0.0,
                "patch_available": False,
                "products": [],
                "cpe_strings": [],
                "affected_versions": [],
                "description": f"CVE {cve} (NVD API error after {MAX_RETRIES} retries)",
                "published": None
            }

        if not results:
            logger.warning(f"No NVD data found for {cve}")
            # Return empty/unknown data instead of unreliable heuristics
            return {
                "severity": "UNKNOWN",
                "cvss_score": 0.0,
                "patch_available": False,
                "products": [],
                "cpe_strings": [],
                "affected_versions": [],
                "description": f"CVE {cve} (no NVD data available)",
                "published": None
            }

        cve_data = results[0]  # Get first (should be only) result

        # Extract CVSS score and severity
        cvss_score = 0.0
        severity = "UNKNOWN"

        # Try to get CVSS v3.1 first, then v3.0, then v2.0
        if hasattr(cve_data, 'v31score') and cve_data.v31score:
            cvss_score = float(cve_data.v31score)
            severity = cve_data.v31severity or "UNKNOWN"
        elif hasattr(cve_data, 'v3score') and cve_data.v3score:
            cvss_score = float(cve_data.v3score)
            severity = cve_data.v3severity or "UNKNOWN"
        elif hasattr(cve_data, 'v2score') and cve_data.v2score:
            cvss_score = float(cve_data.v2score)
            # Convert v2 score to severity approximation
            if cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # Normalize severity to our expected values
        if severity.upper() in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity = severity.upper()
        elif cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        elif cvss_score > 0:
            severity = "LOW"
        else:
            severity = "UNKNOWN"

        # Extract affected products/vendors, CPE strings, and versions
        products = []
        cpe_strings = []
        affected_versions = []
        if hasattr(cve_data, 'cpe') and cve_data.cpe:
            for cpe in cve_data.cpe:  # Process all CPEs
                if hasattr(cpe, 'criteria'):
                    cpe_string = cpe.criteria

                    # Filter out deprecated CPEs
                    if hasattr(cpe, 'deprecated') and cpe.deprecated:
                        continue

                    # Only include valid CPE 2.3 format
                    if cpe_string.startswith('cpe:2.3:'):
                        cpe_strings.append(cpe_string)

                        # Parse CPE string: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                        cpe_parts = cpe_string.split(':')
                        if len(cpe_parts) >= 6:  # Need at least version field
                            vendor = cpe_parts[3]
                            product = cpe_parts[4]
                            version = cpe_parts[5]

                            # Extract human-readable product name
                            if vendor and product and vendor != '*' and product != '*':
                                human_readable = f"{vendor.title()} {product.title()}"
                                if human_readable not in products:
                                    products.append(human_readable)

                            # Extract version information
                            if version and version != '*':
                                # Check if we have version ranges from vulnerable/non-vulnerable configurations
                                version_info = {
                                    "vendor": vendor,
                                    "product": product,
                                    "version": version
                                }

                                # Add additional version context if available
                                if len(cpe_parts) >= 7 and cpe_parts[6] != '*':
                                    version_info["update"] = cpe_parts[6]

                                # Check if this is from a vulnerable configuration
                                if hasattr(cpe, 'vulnerable') and cpe.vulnerable is not None:
                                    version_info["vulnerable"] = cpe.vulnerable
                                else:
                                    version_info["vulnerable"] = True  # Default assumption

                                # Add version range information if available
                                if hasattr(cve_data, 'configurations') and cve_data.configurations:
                                    for config in cve_data.configurations:
                                        if hasattr(config, 'nodes'):
                                            for node in config.nodes:
                                                if hasattr(node, 'cpeMatch'):
                                                    for match in node.cpeMatch:
                                                        if hasattr(match, 'criteria') and match.criteria == cpe_string:
                                                            if hasattr(match, 'versionStartIncluding'):
                                                                version_info["version_start_including"] = match.versionStartIncluding
                                                            if hasattr(match, 'versionStartExcluding'):
                                                                version_info["version_start_excluding"] = match.versionStartExcluding
                                                            if hasattr(match, 'versionEndIncluding'):
                                                                version_info["version_end_including"] = match.versionEndIncluding
                                                            if hasattr(match, 'versionEndExcluding'):
                                                                version_info["version_end_excluding"] = match.versionEndExcluding

                                affected_versions.append(version_info)

        # Determine patch availability (heuristic based on publication date)
        patch_available = False
        if hasattr(cve_data, 'published'):
            import datetime
            try:
                pub_date = datetime.datetime.fromisoformat(cve_data.published.replace('Z', '+00:00'))
                # Assume patches are available if CVE is older than 30 days
                patch_available = (datetime.datetime.now(datetime.timezone.utc) - pub_date).days > 30
            except Exception:
                pass

        result = {
            "severity": severity,
            "cvss_score": cvss_score,
            "patch_available": patch_available,
            "products": products,
            "cpe_strings": cpe_strings,
            "affected_versions": affected_versions,
            "description": getattr(cve_data, 'description', f"CVE {cve}"),
            "published": getattr(cve_data, 'published', None)
        }

        # Cache the result
        _nvd_cache[cve] = result
        return result

    except Exception as e:
        logger.error(f"Error fetching NVD data for {cve}: {e}")
        # Return empty/unknown data instead of unreliable heuristics
        return {
            "severity": "UNKNOWN",
            "cvss_score": 0.0,
            "patch_available": False,
            "products": [],
            "cpe_strings": [],
            "affected_versions": [],
            "description": f"CVE {cve} (enrichment error)",
            "published": None
        }


# Removed enrich_cve_basic() function as it contained unreliable heuristics
# All CVE enrichment now uses official NVD data or returns UNKNOWN


def enrich_cves_offline(cves: List[str], kev_cache: Set[str]) -> CVEEnrichOutput:
    """Enrich CVEs using only KEV data - no heuristics for severity/CVSS."""
    severity = {}
    cvss_score = {}
    patch_available = {}
    products = {}
    cpe_strings = {}
    affected_versions = {}
    active_exploitation = {}

    logger.warning("Using offline mode - CVE data limited to KEV exploitation status only, no severity/CVSS data")

    for cve in cves:
        # Check if in KEV (Known Exploited Vulnerabilities)
        is_exploited = cve in kev_cache

        # Only factual KEV data - no made-up severity or CVSS scores
        severity[cve] = "UNKNOWN"  # We don't know severity without NVD data
        cvss_score[cve] = 0.0  # We don't know CVSS score without NVD data
        patch_available[cve] = False  # Unknown without NVD data
        products[cve] = []  # Unknown without NVD data
        cpe_strings[cve] = []  # Unknown without NVD data
        affected_versions[cve] = []  # Unknown without NVD data
        active_exploitation[cve] = is_exploited  # This is the only factual data we have

        logger.info(f"Offline enriched {cve}: exploited={is_exploited}, all other data unknown")

    return CVEEnrichOutput(
        enriched_cves=[],
        severity=severity,
        cvss_score=cvss_score,
        patch_available=patch_available,
        products=products,
        cpe_strings=cpe_strings,
        affected_versions=affected_versions,
        active_exploitation=active_exploitation
    )


def enrich_cves_with_nvd(cves: List[str], kev_cache: Set[str]) -> CVEEnrichOutput:
    """Enrich CVEs using NVD data with KEV active exploitation status."""
    severity = {}
    cvss_score = {}
    patch_available = {}
    products = {}
    cpe_strings = {}
    affected_versions = {}
    active_exploitation = {}

    logger.info(f"Enriching {len(cves)} CVEs with NVD data (NVDLib handles rate limiting automatically)")

    for cve in cves:
        # Check if in KEV (Known Exploited Vulnerabilities)
        is_exploited = cve in kev_cache

        # Try to get NVD data, return unknown if failed
        # NVDLib automatically handles 6-second delays between requests
        try:
            nvd_info = enrich_cve_with_nvd(cve)
        except Exception as e:
            logger.error(f"Failed to enrich {cve} with NVD: {e}")
            nvd_info = {
                "severity": "UNKNOWN",
                "cvss_score": 0.0,
                "patch_available": False,
                "products": [],
                "cpe_strings": [],
                "affected_versions": [],
                "description": f"CVE {cve} (enrichment failed)",
                "published": None
            }

        severity[cve] = nvd_info.get("severity", "UNKNOWN")
        cvss_score[cve] = nvd_info.get("cvss_score", 0.0)
        patch_available[cve] = nvd_info.get("patch_available", False)
        products[cve] = nvd_info.get("products", [])
        cpe_strings[cve] = nvd_info.get("cpe_strings", [])
        affected_versions[cve] = nvd_info.get("affected_versions", [])
        active_exploitation[cve] = is_exploited

        # Boost severity and CVSS if actively exploited
        if is_exploited:
            if severity[cve] in ["UNKNOWN", "LOW", "MEDIUM"]:
                severity[cve] = "HIGH"
            cvss_score[cve] = max(cvss_score[cve], 7.5)  # Minimum HIGH score for exploited CVEs

        logger.info(f"Enriched {cve}: severity={severity[cve]}, cvss={cvss_score[cve]}, exploited={is_exploited}, versions={len(affected_versions[cve])}")

    return CVEEnrichOutput(
        enriched_cves=[],
        severity=severity,
        cvss_score=cvss_score,
        patch_available=patch_available,
        products=products,
        cpe_strings=cpe_strings,
        affected_versions=affected_versions,
        active_exploitation=active_exploitation
    )


def extract_products_from_text(text: str, cve: str) -> List[str]:
    """Extract affected products from text context around CVE."""
    products = []

    try:
        # Find CVE position in text
        cve_pos = text.lower().find(cve.lower())
        if cve_pos == -1:
            return products

        # Extract context around CVE (500 chars before and after)
        start = max(0, cve_pos - 500)
        end = min(len(text), cve_pos + len(cve) + 500)
        context = text[start:end]

        # Product patterns
        product_patterns = [
            r'\b(microsoft\s+\w+)',
            r'\b(windows\s+[\w\s]*?\d+)',
            r'\b(adobe\s+\w+)',
            r'\b(oracle\s+\w+)',
            r'\b(apache\s+\w+)',
            r'\b(cisco\s+\w+)',
            r'\b(vmware\s+\w+)',
            r'\b(\w+\s+server)',
            r'\b(\w+\s+application)',
        ]

        for pattern in product_patterns:
            matches = re.findall(pattern, context, re.IGNORECASE)
            for match in matches:
                product = match.strip().title()
                if product and product not in products:
                    products.append(product)

    except Exception as e:
        logger.warning(f"Error extracting products for {cve}: {e}")

    return products  # Return all relevant products


def extract_from_text(input_data: CVEExtractInput) -> CVEExtractOutput:
    """Extract CVE identifiers from text using CVEAgent."""
    try:
        from ..orchestrator.agents.cve_agent import CVEAgent
        from ..state import GraphState

        # Create a temporary state with the input text
        state = GraphState(url="", raw_content=input_data.text)

        # Use CVE agent to process the content
        agent = CVEAgent()
        processed_state = agent.process(state)

        # Return the CVEs from the processed state
        cves = processed_state.extracted.get("cve_vulns", [])
        result_cves = [cve.get("id", cve) if isinstance(cve, dict) else cve for cve in cves]

        return CVEExtractOutput(cves=result_cves)

    except Exception as e:
        logger.error(f"Error extracting CVEs: {e}")
        return CVEExtractOutput(cves=[])


def enrich(input_data: CVEEnrichInput) -> CVEEnrichOutput:
    """Enrich CVE data with severity and patch information."""
    try:
        cves = input_data.cves
        prefer_offline = input_data.prefer_offline_cache

        if not cves:
            return CVEEnrichOutput(
                enriched_cves=[],
                severity={},
                cvss_score={},
                patch_available={},
                products={},
                cpe_strings={},
                affected_versions={},
                active_exploitation={}
            )

        # Load KEV cache
        kev_cache = load_kev_cache()
        logger.info(f"Loaded {len(kev_cache)} entries from KEV cache")

        if prefer_offline:
            # Use offline enrichment (heuristics only)
            logger.info("Using offline CVE enrichment with heuristics")
            result = enrich_cves_offline(cves, kev_cache)
        else:
            # Use NVD API enrichment
            logger.info("Using NVD API for CVE enrichment")
            result = enrich_cves_with_nvd(cves, kev_cache)

        logger.info(f"Enriched {len(cves)} CVEs")

        return result

    except Exception as e:
        logger.error(f"Error enriching CVEs: {e}")
        return CVEEnrichOutput(
            enriched_cves=[],
            severity={},
            cvss_score={},
            patch_available={},
            products={},
            cpe_strings={},
            affected_versions={},
            active_exploitation={}
        )


# Tool registrations for MCP
EXTRACT_TOOL = {
    "name": "cve.extract_from_text",
    "description": "Extract CVE identifiers from text",
    "input_schema": CVEExtractInput.model_json_schema(),
    "output_schema": CVEExtractOutput.model_json_schema()
}

ENRICH_TOOL = {
    "name": "cve.enrich",
    "description": "Enrich CVE data with severity and patch information",
    "input_schema": CVEEnrichInput.model_json_schema(),
    "output_schema": CVEEnrichOutput.model_json_schema()
}