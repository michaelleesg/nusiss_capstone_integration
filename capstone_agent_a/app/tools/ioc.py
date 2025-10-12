"""IOC extraction and normalization."""

import json
import logging
import os
import re
from typing import Dict, List, Set, Any
from openai import OpenAI
from urllib.parse import urlparse

import validators
import tldextract
import pathvalidate
from pydantic import BaseModel, Field


class StructuredIOC(BaseModel):
    """IOC with confidence and source information."""
    value: str = Field(description="The IOC value")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    source: str = Field(description="Source/provenance of the IOC")
    ioc_type: str = Field(description="Type of IOC (url, domain, ip, hash, etc.)")

from ..dedup import normalize_domain, normalize_ip, normalize_hash, canonicalize_url

logger = logging.getLogger(__name__)


def _validate_with_validators_library(value: str, ioc_type: str) -> bool:
    """Use validators library for basic IOC validation."""
    try:
        if ioc_type == "url":
            # Clean defanged URLs
            clean_url = value.replace('hxxp', 'http').replace('[.]', '.').replace('[:]', ':')
            return validators.url(clean_url) is True
        elif ioc_type == "domain":
            # Clean defanged domains
            clean_domain = value.replace('[.]', '.').replace('[:]', ':')
            return validators.domain(clean_domain) is True
        elif ioc_type == "ipv4":
            clean_ip = value.replace('[.]', '.').replace('[:]', ':')
            return validators.ipv4(clean_ip) is True
        elif ioc_type == "ipv6":
            clean_ip = value.replace('[.]', '.').replace('[:]', ':')
            return validators.ipv6(clean_ip) is True
        elif ioc_type == "email":
            return validators.email(value) is True
        else:
            return False
    except Exception:
        return False


def _validate_domain_with_tldextract(domain: str) -> bool:
    """Enhanced domain validation using tldextract with Public Suffix List."""
    try:
        # Clean defanged domains first
        clean_domain = domain.replace('[.]', '.').replace('[:]', ':')

        # Extract domain components using tldextract with private suffixes enabled
        # This uses the Public Suffix List to correctly identify TLDs
        extracted = tldextract.extract(clean_domain, include_psl_private_domains=True)

        # Valid domain must have both a domain name and a suffix
        if not extracted.domain or not extracted.suffix:
            return False

        # Check if the domain looks like a file extension
        if _is_file_extension(clean_domain):
            return False

        # Additional validation: domain should not be just numbers
        if extracted.domain.isdigit():
            return False

        # The domain should have reasonable length
        if len(extracted.domain) > 63:  # Max domain label length per RFC
            return False

        # Check for valid characters in domain (basic check)
        import re
        if not re.match(r'^[a-zA-Z0-9\-._]+$', clean_domain):
            return False

        return True

    except Exception:
        return False


def _is_file_extension(domain: str) -> bool:
    """Check if domain appears to be a file extension masquerading as a domain."""
    # Common file extensions that are NOT valid TLDs
    suspicious_extensions = (
        # Executable files
        '.exe', '.dll', '.sys', '.bin', '.bat', '.cmd', '.scr',
        # Java files
        '.class', '.jar', '.war', '.ear',
        # Document files
        '.doc', '.docx', '.pdf', '.txt', '.rtf', '.xls', '.xlsx', '.ppt', '.pptx',
        # Archive files
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        # Image files
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
        # Config/data files
        '.xml', '.json', '.yml', '.yaml', '.cfg', '.conf', '.ini', '.log',
        # Development files
        '.c', '.cpp', '.h', '.py', '.rb', '.pl', '.java', '.cs', '.vb',
        # Web files (that are clearly files, not domains)
        '.php', '.html', '.htm', '.asp', '.jsp', '.cgi', '.js', '.css'
    )

    # Check if the domain ends with a suspicious extension
    # But exclude domains that have actual domain structure (subdomain.domain.tld)
    if domain.endswith(suspicious_extensions):
        # If it looks like "filename.extension" without dots before the extension,
        # it's likely a file masquerading as a domain
        parts = domain.split('.')
        if len(parts) == 2 and parts[0] and not parts[0].isdigit():
            return True

    return False


def _filter_iocs_with_validators(iocs: list, ioc_type: str) -> list:
    """Filter IOCs using tldextract with Public Suffix List and validators library for validation before LLM processing."""
    valid_iocs = []

    for ioc in iocs:
        try:
            if ioc_type == "url":
                if _is_valid_url_format(ioc):
                    valid_iocs.append(ioc)
            elif ioc_type == "domain":
                if _is_valid_domain_format(ioc):
                    valid_iocs.append(ioc)
            elif ioc_type == "ip":
                if _is_valid_ip_format(ioc):
                    valid_iocs.append(ioc)
            else:
                # For unknown types, just pass through
                valid_iocs.append(ioc)
        except Exception as e:
            logger.debug(f"Error validating {ioc_type} '{ioc}': {e}")
            # Skip invalid IOCs
            continue

    filtered_count = len(iocs) - len(valid_iocs)
    if filtered_count > 0:
        logger.info(f"Filtered out {filtered_count} invalid {ioc_type}s using validators library")

    return valid_iocs


def _is_valid_url_format(url: str) -> bool:
    """Validate URL format using validators library first, then custom validation."""
    try:
        if not url or len(url) < 7:  # Minimum: http://a.b
            return False

        # Try validators library first for standard URLs
        if _validate_with_validators_library(url, "url"):
            return True

        # Fallback to custom validation for defanged/threat intel URLs
        parsed = urlparse(url)

        # Must have scheme
        if not parsed.scheme or parsed.scheme not in ('http', 'https'):
            return False

        # Must have netloc (domain)
        if not parsed.netloc:
            return False

        # Check for malformed netloc (no triple slashes, empty netloc, etc.)
        if parsed.netloc == '' or '///' in url:
            return False

        # Special handling for defanged URLs (allow [victim], [domain], etc.)
        netloc = parsed.netloc
        if '[' in netloc and ']' in netloc:
            # This is a defanged URL, which is valid in threat intel context
            return True

        # For regular URLs, netloc must contain at least one dot for domain
        if '.' not in netloc:
            return False

        # Basic domain format validation for IP addresses
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in netloc.split('.') if part):
            # It's an IP address, check if valid
            return _is_valid_ip_format(netloc)

        # Domain validation
        domain_parts = netloc.split('.')
        if len(domain_parts) < 2:
            return False

        # Last part should be valid TLD (at least 2 chars, letters only)
        tld = domain_parts[-1].lower()
        if len(tld) < 2 or not tld.isalpha():
            return False

        return True

    except Exception:
        return False


def _is_valid_domain_format(domain: str) -> bool:
    """Validate domain format using validators library, tldextract with Public Suffix List, then custom validation."""
    try:
        if not domain or len(domain) < 3:  # Minimum: a.b
            return False

        # First try tldextract with Public Suffix List (most comprehensive)
        if _validate_domain_with_tldextract(domain):
            return True

        # Fallback to validators library for standard domains
        if _validate_with_validators_library(domain, "domain"):
            # Additional check for file extensions masquerading as domains
            return not _is_file_extension(domain)

        # Remove brackets if present (defanged) for custom validation
        clean_domain = domain.replace('[.]', '.').replace('[:]', ':')

        # Must contain at least one dot
        if '.' not in clean_domain:
            return False

        # Check for file extensions masquerading as domains
        if _is_file_extension(clean_domain):
            return False

        # Split into parts
        parts = clean_domain.split('.')
        if len(parts) < 2:
            return False

        # Each part should be valid
        for part in parts:
            if not part or len(part) > 63:  # DNS label length limit
                return False
            # Allow letters, numbers, hyphens (but not at start/end)
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', part):
                return False

        # Last part should be valid TLD
        tld = parts[-1].lower()
        if len(tld) < 2 or not tld.isalpha():
            return False

        return True

    except Exception:
        return False


def _is_valid_ip_format(ip: str) -> bool:
    """Validate IP address format, including CIDR ranges."""
    try:
        if not ip:
            return False

        # Check if it's a CIDR range (IP/prefix)
        if '/' in ip:
            try:
                import ipaddress
                # This will validate both IPv4 and IPv6 CIDR ranges
                ipaddress.ip_network(ip, strict=False)
                return True
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                return False

        # Use the validators library for single IP validation
        # validators returns True for valid, ValidationError for invalid
        ipv4_result = validators.ipv4(ip)
        ipv6_result = validators.ipv6(ip)

        return ipv4_result is True or ipv6_result is True

    except Exception:
        return False


def _is_valid_hash_format(hash_value: str) -> bool:
    """Validate cryptographic hash format."""
    try:
        if not hash_value or not isinstance(hash_value, str):
            return False

        # Check if it's all hexadecimal characters
        if not all(c in '0123456789abcdefABCDEF' for c in hash_value):
            return False

        # Check valid hash lengths
        valid_lengths = {32, 40, 64, 128}  # MD5, SHA1, SHA256, SHA512
        return len(hash_value) in valid_lengths

    except Exception:
        return False


def _batch_validate_iocs_with_llm(urls: list, domains: list, ips: list, context_text: str, metadata: dict = None) -> dict:
    """Use LLM to batch validate multiple IOCs at once for better performance."""
    try:
        from openai import OpenAI
        import os
        import json

        # Check if API key is available
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set, using fallback validation")
            return _fallback_batch_validation(urls, domains, ips, context_text, metadata)

        # Skip if no IOCs to validate
        if not urls and not domains and not ips:
            return {"urls": {}, "domains": {}, "ips": {}}

        client = OpenAI(api_key=api_key, timeout=30.0)

        # For large IOC sets, process in multiple batches
        total_iocs = len(urls) + len(domains) + len(ips)
        max_single_batch = 100

        if total_iocs > max_single_batch:
            return _process_large_ioc_set(client, urls, domains, ips, context_text, metadata)
        else:
            return _process_single_batch(client, urls, domains, ips, context_text, metadata)

    except Exception as e:
        logger.error(f"Error in batch LLM IOC validation: {e}")
        return _fallback_batch_validation(urls, domains, ips, context_text)


def _process_single_batch(client, urls: list, domains: list, ips: list, context_text: str, metadata: dict = None) -> dict:
    """Process a single batch of IOCs."""
    # Extract source information from metadata
    source_context = ""
    if metadata:
        source_url = metadata.get('url', '')
        source_title = metadata.get('title', '')
        source_summary = metadata.get('summary', '')
        source_org = metadata.get('source', '')

        # Extract source domains from URL
        source_domains = []
        if source_url:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(source_url)
                if parsed.netloc:
                    source_domains.append(parsed.netloc.lower())
                    # Also add without www
                    if parsed.netloc.startswith('www.'):
                        source_domains.append(parsed.netloc[4:])
            except:
                pass

        source_context = f"""
SOURCE INFORMATION:
- Document URL: {source_url}
- Document Title: {source_title}
- Document Summary: {source_summary}
- Source Organization: {source_org}
- Source Domains: {', '.join(source_domains)}

IMPORTANT: The source domains listed above are the REPORTING organization's domains and should NEVER be marked as malicious IOCs.
CONTEXT: The summary above describes what this document is about and who is reporting the threat intelligence.
"""

        # Debug logging
        logger.info(f"IOC validation with source metadata:")
        logger.info(f"  Source URL: {source_url}")
        logger.info(f"  Source domains to exclude: {source_domains}")
        logger.info(f"  Domain candidates: {domains}")
        logger.info(f"  URL candidates: {urls}")

    system_prompt = f"""You are a cybersecurity analyst validating Indicators of Compromise (IOCs). Your task is to determine which URLs, domains, and IP addresses are actually malicious infrastructure vs legitimate services mentioned in the context.

{source_context}

CRITICAL GUIDELINES:
1. **EXCLUDE SOURCE DOMAINS**: The source domains listed above belong to the reporting organization and are NOT IOCs
2. **DOCUMENT SOURCE ANALYSIS**: Identify additional reporting organizations from the document content
3. **DEFANGED IOCs**: IOCs with [.] or [:] brackets or hxxp protocols are ALWAYS malicious
4. **IOC SECTIONS**: Items listed under explicit headers like "IOCs", "Indicators", "IP Addresses", "Malicious IPs", "URLs/Links" are malicious
5. **CONTEXT ANALYSIS**: Look for phrases like "threat actor", "malicious", "attack infrastructure", "compromise"
6. **LEGITIMATE REFERENCES**: Exclude:
   - Source/reporting organization domains (especially .gov, .mil from government reports)
   - Legitimate service domains mentioned as victims or platforms being attacked
   - Instructional references ("visit", "contact", "report to")
   - Invalid domain formats (file extensions, incomplete domains)
7. **CRITICAL FILE VS DOMAIN DISTINCTION**:
   - **NOT DOMAINS**: File names with extensions (.exe, .dll, .class, .jar, .php, .html, .js, .css, .txt, .doc, .pdf, etc.)
   - **NOT DOMAINS**: Malware file names mentioned in malware analysis (even if they contain dots)
   - **NOT DOMAINS**: Class names, package names, or code artifacts
   - **ACTUAL DOMAINS**: Must have valid internet TLDs (.com, .org, .net, .gov, .edu, .io, .tk, etc.)
   - **ACTUAL DOMAINS**: Must represent network infrastructure or websites, not files
8. **VALIDATION RULES**:
   - Domains must be valid format with proper internet TLD (not file extensions)
   - File artifacts should be classified as malware/files, NOT domains
   - Consider the context: malware analysis vs network infrastructure
   - If it's described as a "file", "malware", "class", or "component", it's NOT a domain

DOCUMENT CONTEXT UNDERSTANDING:
- The source organization's infrastructure is legitimate, not malicious
- Focus on threat actor infrastructure, not victim or reporter infrastructure
- Distinguish between what's being reported ON vs what's doing the reporting
- Distinguish between files/malware and actual network domains

Return ONLY a JSON object with this format:
{{
  "urls": {{"url1": {{"malicious": true/false, "reason": "brief explanation"}}, ...}},
  "domains": {{"domain1": {{"malicious": true/false, "reason": "brief explanation"}}, ...}},
  "ips": {{"ip1": {{"malicious": true/false, "reason": "brief explanation"}}, ...}}
}}"""

    # Chunk context if too long to avoid token limits
    max_context_length = 3000  # chars, roughly 750-1000 tokens
    context_chunks = []

    if len(context_text) <= max_context_length:
        context_chunks = [context_text]
    else:
        # Split into chunks with overlap
        chunk_size = max_context_length
        overlap = 500
        for i in range(0, len(context_text), chunk_size - overlap):
            chunk = context_text[i:i + chunk_size]
            context_chunks.append(chunk)
            if i + chunk_size >= len(context_text):
                break

    # Process all IOCs in reasonable batches
    max_batch_size = 30  # Balance between efficiency and token limits

    # Separate defanged IOCs (higher priority)
    defanged_urls = [url for url in urls if '[' in url or 'hxxp' in url]
    defanged_domains = [domain for domain in domains if '[' in domain]
    defanged_ips = [ip for ip in ips if '[' in ip]

    regular_urls = [url for url in urls if url not in defanged_urls]
    regular_domains = [domain for domain in domains if domain not in defanged_domains]
    regular_ips = [ip for ip in ips if ip not in defanged_ips]

    # Build IOC list for validation (prioritize defanged)
    ioc_list = []

    # Add defanged IOCs first (most likely to be malicious)
    if defanged_urls:
        ioc_list.append(f"DEFANGED URLS:\n" + "\n".join([f"- {url}" for url in defanged_urls[:max_batch_size//3]]))
    if defanged_domains:
        ioc_list.append(f"DEFANGED DOMAINS:\n" + "\n".join([f"- {domain}" for domain in defanged_domains[:max_batch_size//3]]))
    if defanged_ips:
        ioc_list.append(f"DEFANGED IPS:\n" + "\n".join([f"- {ip}" for ip in defanged_ips[:max_batch_size//3]]))

    # Add regular IOCs
    remaining_slots = max_batch_size - len(defanged_urls + defanged_domains + defanged_ips)
    if regular_urls and remaining_slots > 0:
        take_urls = min(len(regular_urls), remaining_slots//3)
        ioc_list.append(f"URLS:\n" + "\n".join([f"- {url}" for url in regular_urls[:take_urls]]))
        remaining_slots -= take_urls

    if regular_domains and remaining_slots > 0:
        take_domains = min(len(regular_domains), remaining_slots//2)
        ioc_list.append(f"DOMAINS:\n" + "\n".join([f"- {domain}" for domain in regular_domains[:take_domains]]))
        remaining_slots -= take_domains

    if regular_ips and remaining_slots > 0:
        ioc_list.append(f"IP ADDRESSES:\n" + "\n".join([f"- {ip}" for ip in regular_ips[:remaining_slots]]))

    # Use the most relevant context chunk (first one usually contains document type/headers)
    primary_context = context_chunks[0] if context_chunks else ""

    user_prompt = f"""Analyze these potential IOCs and determine which are malicious infrastructure based on the document context:

{chr(10).join(ioc_list)}

DOCUMENT CONTEXT:
{primary_context}

ANALYSIS GUIDELINES:
- Defanged IOCs (with [.] or [:] brackets or hxxp) are almost always malicious
- Consider the document type and purpose when evaluating IOCs
- Look for context clues indicating whether IPs/URLs/domains are malicious infrastructure vs. legitimate services mentioned as targets
- IOCs listed in dedicated indicator sections should be considered malicious
- Consider whether this appears to be a threat intelligence report vs. other document types

For each IOC, determine if it represents malicious infrastructure or is just mentioned as a reference/target."""

    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o"),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        max_tokens=2000,
        temperature=0.1
    )

    response_text = response.choices[0].message.content.strip()

    try:
        # Parse JSON response
        if "```json" in response_text:
            json_start = response_text.find("```json") + 7
            json_end = response_text.find("```", json_start)
            json_text = response_text[json_start:json_end].strip()
        elif response_text.startswith("{"):
            json_text = response_text
        else:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start != -1 and json_end > json_start:
                json_text = response_text[json_start:json_end]
            else:
                logger.warning(f"Invalid batch IOC validation response")
                return _fallback_batch_validation(urls, domains, ips, context_text, metadata)

        result = json.loads(json_text)
        logger.info(f"Single batch IOC validation completed: {len(urls)} URLs, {len(domains)} domains, {len(ips)} IPs")

        # Debug logging for domain validation results
        if domains and result.get("domains"):
            logger.info(f"Domain validation results:")
            for domain in domains:
                domain_result = result.get("domains", {}).get(domain, {})
                malicious = domain_result.get("malicious", False)
                reason = domain_result.get("reason", "unknown")
                logger.info(f"  {domain}: malicious={malicious}, reason={reason}")

        return result

    except json.JSONDecodeError:
        logger.warning(f"Invalid LLM response for single batch IOC validation: {response_text[:200]}")
        return _fallback_batch_validation(urls, domains, ips, context_text)


def _fallback_batch_validation(urls: list, domains: list, ips: list, context_text: str, metadata: dict = None) -> dict:
    """Fallback batch validation using pattern-based approach."""
    result = {"urls": {}, "domains": {}, "ips": {}}

    # Extract source domains from metadata to exclude them
    source_domains = []
    if metadata:
        source_url = metadata.get('url', '')
        if source_url:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(source_url)
                if parsed.netloc:
                    source_domains.append(parsed.netloc.lower())
                    # Also add without www
                    if parsed.netloc.startswith('www.'):
                        source_domains.append(parsed.netloc[4:])
            except:
                pass

    # Use individual fallback for each IOC
    for url in urls:
        result["urls"][url] = {"malicious": _fallback_ioc_validation(url, "url", context_text, metadata), "reason": "fallback validation"}

    for domain in domains:
        # Always exclude source domains
        if domain.lower() in source_domains:
            result["domains"][domain] = {"malicious": False, "reason": "source domain - excluded"}
        else:
            result["domains"][domain] = {"malicious": _fallback_ioc_validation(domain, "domain", context_text, metadata), "reason": "fallback validation"}

    for ip in ips:
        result["ips"][ip] = {"malicious": _fallback_ioc_validation(ip, "ip", context_text, metadata), "reason": "fallback validation"}

    return result


def _process_large_ioc_set(client, urls: list, domains: list, ips: list, context_text: str, metadata: dict = None) -> dict:
    """Process large IOC sets by batching and using smart fallbacks."""
    # For very large IOC sets (100+ IPs like in the FBI report), use a simplified approach
    # that processes defanged IOCs with LLM and regular IOCs with pattern-based validation

    result = {"urls": {}, "domains": {}, "ips": {}}

    # Separate defanged from regular IOCs
    defanged_urls = [url for url in urls if '[' in url or 'hxxp' in url]
    defanged_domains = [domain for domain in domains if '[' in domain]
    defanged_ips = [ip for ip in ips if '[' in ip]

    regular_urls = [url for url in urls if url not in defanged_urls]
    regular_domains = [domain for domain in domains if domain not in defanged_domains]
    regular_ips = [ip for ip in ips if ip not in defanged_ips]

    # Process defanged IOCs with pattern-based validation (these are almost always malicious)
    if defanged_urls or defanged_domains or defanged_ips:
        # For defanged IOCs, skip LLM processing and mark as malicious
        for url in defanged_urls:
            result["urls"][url] = {"malicious": True, "reason": "Defanged URL format indicates threat intelligence IOC"}
        for domain in defanged_domains:
            result["domains"][domain] = {"malicious": True, "reason": "Defanged domain format indicates threat intelligence IOC"}
        for ip in defanged_ips:
            result["ips"][ip] = {"malicious": True, "reason": "Defanged IP format indicates threat intelligence IOC"}

    # For regular IOCs in large threat intel docs, use context-aware fallback
    # Check if this appears to be a threat intelligence document
    context_lower = context_text.lower()
    appears_threat_intel = any(indicator in context_lower for indicator in [
        'indicators', 'iocs', 'malicious', 'threat actor', 'compromise'
    ])

    if appears_threat_intel:
        # Extract source domains for exclusion
        source_domains = []
        if metadata:
            source_url = metadata.get('url', '')
            if source_url:
                from urllib.parse import urlparse
                try:
                    parsed = urlparse(source_url)
                    if parsed.netloc:
                        source_domains.append(parsed.netloc.lower())
                        # Also add without www
                        if parsed.netloc.startswith('www.'):
                            source_domains.append(parsed.netloc[4:])
                except:
                    pass

        # In threat intel docs, most IPs in IOC sections are malicious
        # Use pattern-based validation with high confidence
        for ip in regular_ips:
            result["ips"][ip] = {"malicious": True, "reason": "Listed in threat intelligence IOC section"}

        for url in regular_urls:
            # URLs are more context-dependent, use fallback validation
            is_malicious = _fallback_ioc_validation(url, "url", context_text, metadata)
            result["urls"][url] = {"malicious": is_malicious, "reason": "Context-based validation"}

        for domain in regular_domains:
            # Always exclude source domains
            if domain.lower() in source_domains:
                result["domains"][domain] = {"malicious": False, "reason": "source domain - excluded"}
            else:
                # Domains are more context-dependent, use fallback validation
                is_malicious = _fallback_ioc_validation(domain, "domain", context_text, metadata)
                result["domains"][domain] = {"malicious": is_malicious, "reason": "Context-based validation"}
    else:
        # Not a threat intel doc, use conservative fallback validation
        fallback_result = _fallback_batch_validation(regular_urls, regular_domains, regular_ips, context_text, metadata)
        result["urls"].update(fallback_result.get("urls", {}))
        result["domains"].update(fallback_result.get("domains", {}))
        result["ips"].update(fallback_result.get("ips", {}))

    logger.info(f"Large IOC set processed: {len(urls)} URLs, {len(domains)} domains, {len(ips)} IPs")
    return result


def _validate_ioc_with_llm(ioc: str, ioc_type: str, context_text: str) -> bool:
    """Use LLM to validate if an IOC is actually malicious based on context."""
    try:
        from openai import OpenAI
        import os
        import json

        # Check if API key is available
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set, using fallback validation")
            return _fallback_ioc_validation(ioc, ioc_type, context_text)

        client = OpenAI(api_key=api_key, timeout=30.0)

        system_prompt = """You are a cybersecurity analyst validating Indicators of Compromise (IOCs). Your task is to determine if a given URL, domain, or IP address is actually malicious infrastructure or just a legitimate service mentioned in the context.

CRITICAL GUIDELINES:
1. Defanged IOCs (with [.] or [:] brackets) are ALWAYS considered malicious - return true
2. Legitimate services mentioned as TARGETS or VICTIMS are NOT IOCs - return false
3. URLs/domains only mentioned in instructional context (like "visit X" or "go to Y") are NOT IOCs - return false
4. Look for explicit malicious context: C2, phishing, malware hosting, compromised infrastructure
5. Government domains (.gov, .mil, .sg) are typically targets, not threats - return false unless explicitly compromised

Return ONLY a JSON object with this format:
{"is_malicious": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}"""

        user_prompt = f"""Analyze this {ioc_type} and determine if it's a malicious IOC:

{ioc_type.upper()}: {ioc}

CONTEXT:
{context_text[:1000]}

Is this {ioc_type} malicious infrastructure or just mentioned as a target/reference?"""

        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            max_tokens=200
        )

        response_text = response.choices[0].message.content.strip()

        # Parse JSON response
        if "```json" in response_text:
            json_start = response_text.find("```json") + 7
            json_end = response_text.find("```", json_start)
            json_text = response_text[json_start:json_end].strip()
        elif response_text.startswith("{"):
            json_text = response_text
        else:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start != -1 and json_end > json_start:
                json_text = response_text[json_start:json_end]
            else:
                logger.warning(f"Invalid LLM response for IOC validation: {response_text}")
                return True  # Default to including if can't parse

        result = json.loads(json_text)
        is_malicious = result.get("is_malicious", True)
        confidence = result.get("confidence", 0.5)
        reason = result.get("reason", "")

        logger.debug(f"IOC validation for {ioc}: malicious={is_malicious}, confidence={confidence}, reason={reason}")

        # Only include high-confidence results
        return is_malicious and confidence >= 0.6

    except Exception as e:
        logger.error(f"Error in LLM IOC validation: {e}")
        # Fallback: include if defanged, otherwise be conservative
        return _fallback_ioc_validation(ioc, ioc_type, context_text)


def _fallback_ioc_validation(ioc: str, ioc_type: str, context_text: str, metadata: dict = None) -> bool:
    """Simple fallback validation when LLM is not available."""
    # Always include defanged IOCs (clear indicators of threat intelligence)
    defang_indicators = ['[.]', '[:]', 'hxxp', '[victim]', '[domain]', '[ip]', '[host]']
    if any(indicator in ioc for indicator in defang_indicators):
        return True

    # Check if the original context contained defanged notation for this IOC
    # This handles cases where normalization removed the brackets
    if context_text:
        # Look for defanged version of this IOC in context
        ioc_defanged_variants = [
            ioc.replace('.', '[.]'),
            ioc.replace(':', '[:]'),
            ioc.replace('http', 'hxxp')
        ]
        if any(variant in context_text for variant in ioc_defanged_variants):
            return True

    # Include if found in explicit IOC/indicator sections
    threat_context_keywords = [
        'indicator', 'ioc', 'indicators of compromise', 'threat', 'malicious',
        'compromise', 'attack', 'adversary', 'campaign', 'actor', 'apt', 'unc',
        'exploit', 'c2', 'command and control', 'phishing', 'malware'
    ]
    context_lower = context_text.lower() if context_text else ""

    # If we're clearly in a threat intelligence document, be more inclusive
    if any(keyword in context_lower for keyword in threat_context_keywords):
        # But exclude clearly legitimate services mentioned as targets
        legitimate_exclusions = [
            'microsoft.com', 'google.com', 'amazon.com', 'salesforce.com',
            'github.com', 'stackoverflow.com', '.gov', '.edu', '.mil'
        ]
        # Exclude if it's clearly a legitimate service (unless it was defanged, which indicates threat context)
        if any(exclusion in ioc.lower() for exclusion in legitimate_exclusions):
            # Only exclude if it wasn't originally defanged
            if not any(variant in context_text for variant in [
                ioc.replace('.', '[.]'),
                ioc.replace(':', '[:]'),
                ioc.replace('http', 'hxxp')
            ]):
                return False
        # If not excluded above, include it as potentially malicious
        return True

    # Conservative fallback - only include if clearly suspicious
    suspicious_patterns = [
        r'\d+\.\d+\.\d+\.\d+',  # Raw IP addresses
        r'[a-z0-9]{10,}\.com',   # Long random domains
        r'\.tk$|\.ml$|\.ga$|\.cf$',  # Suspicious TLDs
        r'[0-9]+-[0-9]+-[0-9]+', # Date-like patterns in domains
    ]

    import re
    return any(re.search(pattern, ioc, re.IGNORECASE) for pattern in suspicious_patterns)


def _normalize_ioc_url(url: str) -> str:
    """Minimal normalization for IOC URLs to preserve original format."""
    # Only basic cleanup - preserve case, paths, and parameters
    url = url.strip()

    # Ensure consistent protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Remove only trailing whitespace and common punctuation
    url = url.rstrip('.,;:!?')

    return url


def _is_likely_malicious_url(url: str, context_text: str) -> bool:
    """Determine if a URL is likely malicious using LLM validation."""
    return _validate_ioc_with_llm(url, "url", context_text)


class IOCInput(BaseModel):
    """Input for IOC extraction."""

    text: str = Field(description="Text to extract IOCs from")
    metadata: dict = Field(default_factory=dict, description="Document metadata including source URL and organization")


class IOCOutput(BaseModel):
    """Output for IOC extraction organized by network/host/behavioral categories."""

    # Organized IOCs matching requirements schema
    iocs: Dict[str, List[StructuredIOC]] = Field(default_factory=lambda: {
        "network": [],   # URLs, domains, IPs
        "host": [],      # File paths, hashes, registry keys
        "behavioral": [] # Processes, commands, patterns
    }, description="IOCs organized by category")

    # Legacy fields for backward compatibility
    urls: List[str] = Field(default_factory=list, description="URLs (deprecated - use iocs.network)")
    domains: List[str] = Field(default_factory=list, description="Domains (deprecated - use iocs.network)")
    ips: List[str] = Field(default_factory=list, description="IPs (deprecated - use iocs.network)")
    hashes: List[str] = Field(default_factory=list, description="Hashes (deprecated - use iocs.host)")

    # Additional IOC fields expected by agents
    file_paths: List[str] = Field(default_factory=list, description="File paths")
    processes: List[str] = Field(default_factory=list, description="Process names")
    registry_keys: List[str] = Field(default_factory=list, description="Registry keys")
    commands: List[str] = Field(default_factory=list, description="Command lines")
    email_addresses: List[str] = Field(default_factory=list, description="Email addresses")

    # Pre-filtered non-routable IPs (for agent exclusions)
    non_routable_ips: List[Dict[str, Any]] = Field(default_factory=list, description="Non-routable IPs with exclusion reasons")


def extract_urls(text: str, full_context: str = None) -> Set[str]:
    """Extract URLs from text."""
    url_patterns = [
        # Standard HTTP/HTTPS URLs with optional port numbers
        r'https?://[^\s<>"\'`]+',
        # Defanged URLs with protocol brackets
        r'https?\[:\]//[^\s<>"\'`]+',
        r'hxxps?\[:\]//[^\s<>"\'`]+',
        # Defanged IP URLs with port numbers - enhanced pattern
        r'https?://[0-9]{1,3}(?:\[\.\])[0-9]{1,3}(?:\[\.\])[0-9]{1,3}(?:\[\.\])[0-9]{1,3}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?',
        r'hxxps?://[0-9]{1,3}(?:\[\.\])[0-9]{1,3}(?:\[\.\])[0-9]{1,3}(?:\[\.\])[0-9]{1,3}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?',
        # Mixed defanged IP URLs (some dots normal, some bracketed)
        r'https?://[0-9]{1,3}(?:\.|\[\.\])[0-9]{1,3}(?:\.|\[\.\])[0-9]{1,3}(?:\.|\[\.\])[0-9]{1,3}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?',
        r'hxxps?://[0-9]{1,3}(?:\.|\[\.\])[0-9]{1,3}(?:\.|\[\.\])[0-9]{1,3}(?:\.|\[\.\])[0-9]{1,3}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?',
        # Full defanged domain URLs with port numbers
        r'https?://[a-zA-Z0-9-]+(?:\[\.\])[a-zA-Z0-9-]+(?:\[\.\])[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?(?:\?[^\s<>"\'`,]*)?',
        r'hxxps?://[a-zA-Z0-9-]+(?:\[\.\])[a-zA-Z0-9-]+(?:\[\.\])[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?(?:\?[^\s<>"\'`,]*)?',
        # Full defanged URLs (any number of subdomains with paths/query)
        r'[a-zA-Z0-9-]+(?:\[\.\][a-zA-Z0-9-]+){1,}\[\.\][a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?(?:\?[^\s<>"\'`,]*)?',
        # URLs with placeholder victims/variables in brackets
        r'https?://[a-zA-Z0-9-]+\[[a-zA-Z0-9_-]+\]\.[a-zA-Z0-9-.]+(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?(?:\?[^\s<>"\'`,]*)?',
        # Mixed defanged URLs (some dots normal, some bracketed) - must contain at least one [.]
        r'[a-zA-Z0-9-]+(?:\.|\[\.\])[a-zA-Z0-9-]+(?:\.|\[\.\])[a-zA-Z0-9-]+(?:\.|\[\.\])*[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s<>"\'`,]*)?(?:\?[^\s<>"\'`,]*)?(?=.*\[\.\])',
        # Regular URLs with paths and port numbers (must have path or query to avoid matching every domain)
        r'(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s<>"\'`,]+|\?[^\s<>"\'`,]+)',
        r'(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\s<>"\'`,]+|\?[^\s<>"\'`,]+)',
        # Simple domains only for specific suspicious TLDs or patterns
        r'[a-zA-Z0-9-]+\.(?:tk|ml|ga|cf|bit|onion)(?::[0-9]+)?(?!\S)',
        # Simple defanged domains (no path/query)
        r'[a-zA-Z0-9-]+(?:\[\.\][a-zA-Z0-9-]+)+\[\.\][a-zA-Z]{2,}(?::[0-9]+)?(?!\S)',
    ]

    urls = set()

    for pattern in url_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Clean and normalize URL - handle command boundaries and quotes
            url = match.strip('.,;:!?()[]{}"\' \t\n\r,')

            # Remove trailing characters common in command contexts
            url = re.sub(r'[,\'"]+$', '', url)

            # Skip if it looks like an email
            if '@' in url and not url.startswith(('http://', 'https://')):
                continue

            # Skip if it looks like a CIDR range that got mangled into a URL
            # Pattern: https://IP/CIDR or similar with trailing chars
            if re.match(r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}', url):
                continue

            # Skip URLs that end with CIDR notation and have extra characters
            if re.search(r'/[0-9]{1,2}[\]\'\s]*$', url):
                continue

            # Skip URLs that are clearly CIDR ranges in disguise (after cleaning)
            # Check if removing protocol gives us a valid CIDR range
            url_without_protocol = re.sub(r'https?://', '', url)
            if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$', url_without_protocol):
                continue

            # Fix defanged URLs
            url = re.sub(r'\[\.\]', '.', url)
            url = re.sub(r'\[:\]', ':', url)
            url = re.sub(r'hxxp', 'http', url, flags=re.IGNORECASE)

            # Add protocol if missing and it looks like a legitimate domain
            if not url.startswith(('http://', 'https://')) and '.' in url:
                # Basic domain validation before adding protocol
                domain_part = url.split('/')[0].split('?')[0]
                parts = domain_part.split('.')

                # Only add protocol if it looks like a real domain structure
                # Must have at least 2 parts and TLD should be reasonable length
                if len(parts) >= 2 and len(parts[-1]) >= 2:
                    # Additional check: if it's just filename.extension, don't treat as domain
                    # Look for common file extensions that shouldn't be domains
                    if len(parts) == 2:
                        first_part = parts[0].lower()
                        second_part = parts[1].lower()

                        # Skip obvious file patterns like "hello.php", "index.html", etc.
                        if (len(first_part) < 15 and  # Short first part
                            second_part in ['php', 'html', 'htm', 'asp', 'jsp', 'js', 'css', 'txt', 'xml', 'json']):
                            continue

                    url = 'https://' + url

            # Validate URL structure and domain
            if validators.url(url):
                # Additional validation: check if domain part is reasonable
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    domain = parsed.netloc.lower()

                    # Skip URLs with invalid domains
                    if not domain or '.' not in domain:
                        continue

                except Exception:
                    continue

                # Check if it's actually malicious, not just mentioned
                # Check original (possibly defanged) URL for validation
                original_url = url  # Keep original for validation
                if _is_likely_malicious_url(original_url, full_context or text):
                    # For IOCs, preserve original format with minimal normalization
                    normalized_url = _normalize_ioc_url(url)
                    urls.add(normalized_url)

    return urls


def extract_stix_patterns(text: str) -> Dict[str, Set[str]]:
    """Extract IOCs from STIX indicator patterns with exclusion tracking."""
    stix_iocs = {
        'domains': set(),
        'ips': set(),
        'urls': set(),
        'hashes': set(),
        'excluded_values': set()  # Values that should not be processed by regular patterns
    }

    # Find STIX indicator patterns in text
    stix_pattern_regex = r'STIX_INDICATOR_PATTERN:\s*\[([^\]]+)\]'
    patterns = re.findall(stix_pattern_regex, text)

    for pattern in patterns:
        try:
            # Parse domain-name patterns: domain-name:value = 'example.com'
            domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
            if domain_match:
                domain = domain_match.group(1)
                stix_iocs['excluded_values'].add(domain)  # Mark as processed
                if _is_valid_domain_format(domain):
                    stix_iocs['domains'].add(domain)

            # Parse IPv4 patterns: ipv4-addr:value = '1.2.3.4'
            ipv4_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
            if ipv4_match:
                ip = ipv4_match.group(1)
                stix_iocs['excluded_values'].add(ip)  # Mark as processed
                if _is_valid_ip_format(ip):
                    stix_iocs['ips'].add(ip)

            # Parse IPv6 patterns: ipv6-addr:value = '2001:db8::1'
            ipv6_match = re.search(r"ipv6-addr:value\s*=\s*'([^']+)'", pattern)
            if ipv6_match:
                ip = ipv6_match.group(1)
                stix_iocs['excluded_values'].add(ip)  # Mark as processed
                if _is_valid_ip_format(ip):
                    stix_iocs['ips'].add(ip)

            # Parse URL patterns: url:value = 'http://example.com'
            url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
            if url_match:
                url = url_match.group(1)
                stix_iocs['excluded_values'].add(url)  # Mark as processed
                if _is_valid_url_format(url):
                    stix_iocs['urls'].add(url)

            # Parse file hash patterns: file:hashes.MD5 = 'abcd1234'
            hash_patterns = [
                r"file:hashes\.MD5\s*=\s*'([^']+)'",
                r"file:hashes\.SHA-1\s*=\s*'([^']+)'",
                r"file:hashes\.SHA-256\s*=\s*'([^']+)'",
                r"file:hashes\.SHA-512\s*=\s*'([^']+)'"
            ]
            for hash_pattern in hash_patterns:
                hash_match = re.search(hash_pattern, pattern)
                if hash_match:
                    hash_value = hash_match.group(1)
                    stix_iocs['excluded_values'].add(hash_value)  # Mark as processed
                    if _is_valid_hash_format(hash_value):
                        stix_iocs['hashes'].add(hash_value)

            # Handle non-IOC patterns that should be excluded from regular extraction
            # x509-certificate:serial_number = '4c:b:1d:19:74:86:a7:66'
            x509_match = re.search(r"x509-certificate:serial_number\s*=\s*'([^']+)'", pattern)
            if x509_match:
                cert_serial = x509_match.group(1)
                stix_iocs['excluded_values'].add(cert_serial)  # Mark as excluded, don't extract as IOC
                logger.info(f"Excluded x509 certificate serial from IOC extraction: {cert_serial}")

            # MAC addresses: ethernet-addr:value = '00:11:22:33:44:55'
            mac_match = re.search(r"ethernet-addr:value\s*=\s*'([^']+)'", pattern)
            if mac_match:
                mac_addr = mac_match.group(1)
                stix_iocs['excluded_values'].add(mac_addr)  # Mark as excluded, don't extract as IOC
                logger.info(f"Excluded MAC address from IOC extraction: {mac_addr}")

            # Debug: Log unhandled patterns that might contain colon-separated hex
            if ':' in pattern and not any([domain_match, ipv4_match, ipv6_match, url_match, x509_match, mac_match]):
                # Check if this pattern contains values that look like certificate serials or MAC addresses
                potential_values = re.findall(r"=\s*'([^']*:[^']*)'", pattern)
                for value in potential_values:
                    if ':' in value and all(len(part) <= 4 and all(c in '0123456789abcdefABCDEF' for c in part) for part in value.split(':')):
                        logger.warning(f"Unhandled STIX pattern with colon-separated hex value: {pattern}")
                        stix_iocs['excluded_values'].add(value)  # Exclude it anyway

        except Exception as e:
            logger.warning(f"Error parsing STIX pattern '{pattern}': {e}")

    return stix_iocs


def extract_domains(text: str) -> Set[str]:
    """Extract domain names from text with LLM validation."""
    domain_patterns = [
        # Standard domains (but NOT if they have paths or query parameters)
        r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![/\?\s]*[^\s])',
        # Defanged domains with brackets (but NOT if they have paths or query parameters)
        r'\b(?:[a-zA-Z0-9-]+\[\.\])+[a-zA-Z]{2,}(?![/\?\s]*[^\s])',
        # Complex defanged domains (but NOT if they have paths or query parameters)
        r'\b[a-zA-Z0-9-]+(?:\[\.\][a-zA-Z0-9-]+)+\[\.\][a-zA-Z]{2,}(?![/\?\s]*[^\s])',
        # Mixed defanged patterns (but NOT if they have paths or query parameters)
        r'\b[a-zA-Z0-9-]+\[\.\][a-zA-Z0-9.-]+(?![/\?\s]*[^\s])',
    ]

    domains = set()

    for pattern in domain_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Clean domain
            domain = match.strip('.,;:!?()[]{}"\' \t\n\r')
            original_domain = domain  # Keep original for validation

            # Fix defanged domains for validation
            domain = re.sub(r'\[\.\]', '.', domain)

            # Skip if it looks like a file extension or version number
            if re.match(r'^\d+\.\d+$', domain) or domain.endswith(('.exe', '.dll', '.pdf', '.doc')):
                continue

            # Skip common false positives
            false_positives = {
                'e.g.', 'i.e.', 'etc.', 'vs.', 'no.', 'inc.', 'ltd.', 'corp.',
                '127.0.0.1', 'localhost', '0.0.0.0', '255.255.255.255'
            }
            if domain.lower() in false_positives:
                continue

            # Validate domain format
            if validators.domain(domain) and len(domain) > 3:
                # Use validation to determine if this is actually malicious
                if _validate_ioc_with_llm(original_domain, "domain", text):
                    normalized = normalize_domain(domain)
                    domains.add(normalized)

    return domains


def extract_ips(text: str) -> Set[str]:
    """Extract IP addresses from text with LLM validation."""
    # First, extract CIDR ranges to avoid duplicating the network portion
    cidr_patterns = [
        # IPv4 CIDR ranges
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/[0-9]{1,2}\b',
        # Defanged IPv4 CIDR ranges
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\]){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/[0-9]{1,2}\b',
    ]

    individual_ip_patterns = [
        # IPv4 addresses
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        # IPv6 addresses (simplified)
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{0,4}\b',
        # Defanged IPs
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\]){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    ]

    ips = set()
    found_cidrs = set()

    # First extract CIDR ranges
    for pattern in cidr_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            original_cidr = match
            # Fix defanged CIDR ranges
            cidr = re.sub(r'\[\.\]', '.', match)

            if _is_valid_ip_format(cidr):
                # Store both the CIDR and the network portion for deduplication
                found_cidrs.add(cidr)
                network_ip = cidr.split('/')[0]
                found_cidrs.add(network_ip)  # Prevent extracting the network IP separately
                ips.add(cidr)

    # Then extract individual IPs, but skip ones already found as CIDR networks
    for pattern in individual_ip_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            original_ip = match  # Keep original for validation
            # Fix defanged IPs
            ip = re.sub(r'\[\.\]', '.', match)

            # Skip if this IP is already part of a CIDR range we found
            if ip in found_cidrs:
                continue

            # Skip private/reserved ranges for most cases unless they're defanged
            private_patterns = [
                r'^10\.',
                r'^192\.168\.',
                r'^172\.(1[6-9]|2[0-9]|3[01])\.',
                r'^127\.',
                r'^169\.254\.',
                r'^224\.',  # Multicast
                r'^0\.',    # Invalid
                r'^255\.255\.255\.255$',  # Broadcast
            ]

            is_private = any(re.match(pattern, ip) for pattern in private_patterns)

            # If it's defanged, it's likely an IOC regardless of being private
            if '[.]' in original_ip:
                is_private = False

            if is_private:
                # Use basic context check for private IPs
                context_window = 100
                ip_pos = text.find(match)
                if ip_pos != -1:
                    context = text[max(0, ip_pos-context_window):ip_pos+len(match)+context_window].lower()
                    threat_context = any(word in context for word in [
                        'malware', 'c2', 'command', 'control', 'beacon', 'callback',
                        'threat', 'attack', 'compromise', 'infrastructure'
                    ])
                    if not threat_context:
                        continue

            if validators.ipv4(ip) or validators.ipv6(ip):
                # Use LLM validation for non-private IPs or defanged IPs
                if not is_private or '[.]' in original_ip:
                    if _validate_ioc_with_llm(original_ip, "ip", text):
                        ips.add(normalize_ip(ip))
                else:
                    # Private IPs that passed threat context check
                    ips.add(normalize_ip(ip))

    return ips


def filter_routable_ips(ip_candidates: set) -> tuple:
    """
    Filter IP candidates into routable and non-routable using deterministic classification.

    Returns:
        Tuple of (routable_ips, non_routable_ips_with_reasons)
    """
    if not ip_candidates:
        return set(), []

    try:
        from .ip_classifier import classify_ip_addresses, IPClassificationInput

        # Convert set to list for classification
        ip_list = list(ip_candidates)

        # Classify all IPs deterministically
        classification_input = IPClassificationInput(ips=ip_list)
        classification_result = classify_ip_addresses(classification_input)

        # Convert results
        routable_ips = set(classification_result.routable)

        non_routable_with_reasons = []
        for non_routable in classification_result.non_routable:
            non_routable_with_reasons.append({
                "ioc": non_routable.ip,
                "reason": non_routable.reason
            })

        logger.info(f"IP filtering: {len(routable_ips)} routable, {len(non_routable_with_reasons)} non-routable")
        return routable_ips, non_routable_with_reasons

    except Exception as e:
        logger.error(f"Error in IP filtering: {e}")
        # Fallback: treat all as routable
        return ip_candidates, []


def extract_hashes(text: str) -> Set[str]:
    """Extract cryptographic hashes from text."""
    hash_patterns = [
        # MD5 (32 hex chars)
        r'\b[a-fA-F0-9]{32}\b',
        # SHA1 (40 hex chars)
        r'\b[a-fA-F0-9]{40}\b',
        # SHA256 (64 hex chars)
        r'\b[a-fA-F0-9]{64}\b',
        # SHA512 (128 hex chars)
        r'\b[a-fA-F0-9]{128}\b',
    ]

    hashes = set()

    for pattern in hash_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Normalize hash
            hash_value = normalize_hash(match)

            # Validate hash length
            if len(hash_value) in (32, 40, 64, 128):
                # Skip if it's all the same character (likely placeholder)
                if len(set(hash_value)) > 1:
                    hashes.add(hash_value)

    return hashes


def extract_file_hashes_from_attributes(text: str) -> Set[str]:
    """Extract hashes that are explicitly labeled as file hashes."""
    labeled_patterns = [
        r'(?:md5|sha1|sha256|sha512)[\s:=]+([a-fA-F0-9]{32,128})',
        r'(?:hash|checksum)[\s:=]+([a-fA-F0-9]{32,128})',
        r'([a-fA-F0-9]{32,128})[\s]*(?:\(md5\)|\(sha1\)|\(sha256\)|\(sha512\))',
    ]

    hashes = set()

    for pattern in labeled_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            hash_value = normalize_hash(match)
            if len(hash_value) in (32, 40, 64, 128) and len(set(hash_value)) > 1:
                hashes.add(hash_value)

    return hashes


def extract_file_paths(text: str) -> Set[str]:
    """Extract file paths using pathvalidate for validation."""
    # Enhanced patterns for file paths
    basic_patterns = [
        # Windows paths
        r'[A-Za-z]:\\[^\\/:*?"<>|\r\n]+\\[^\\/:*?"<>|\r\n]+\.[a-zA-Z0-9]{2,5}',
        r'[A-Za-z]:\\[^\\/:*?"<>|\r\n]+\\[^\\/:*?"<>|\r\n]+',  # Windows paths without extension
        # Unix/Linux paths
        r'/(?:tmp|var|home|opt|usr|etc|bin|sbin|root|boot|dev|proc|sys|lib|lib64|run|srv|mnt|media)/[^/\s]+(?:/[^/\s]+)*(?:\.[a-zA-Z0-9]{2,5})?',
        r'/[^/\s]+/[^/\s]+\.[a-zA-Z0-9]{2,5}',  # Generic Unix paths with extensions
        # Relative paths
        r'\.{1,2}/[^/\s]+(?:/[^/\s]+)*(?:\.[a-zA-Z0-9]{2,5})?',
        # Common malware paths
        r'%[A-Z_]+%\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*',  # Windows environment variables
    ]

    file_paths = set()

    for pattern in basic_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            path = match.strip('\'"')

            # Skip URLs and web content
            if any(x in path.lower() for x in ['http', 'www', 'ftp://', 'sftp://', '[.]']):
                continue

            # Skip very short paths
            if len(path) < 4:
                continue

            # Use pathvalidate to validate the path
            if _validate_file_path(path):
                file_paths.add(path)

    return file_paths


def _validate_file_path(path: str) -> bool:
    """Validate file path using pathvalidate library."""
    try:
        # Basic length check
        if len(path) < 4 or len(path) > 4096:  # Max path length on most systems
            return False

        # Check for obvious non-paths
        if any(x in path.lower() for x in [
            'http', 'www', 'mailto:', 'javascript:', 'data:',
            'about:', 'chrome:', 'file://', 'ftp://', 'ssh://',
            '[.]', 'hxxp', 'suspicious', 'detected', 'blocked'
        ]):
            return False

        # Use pathvalidate to check if it's a valid path format
        # This handles platform-specific validation (Windows/Unix)
        try:
            # Validate as both Windows and Unix path to be platform-agnostic
            pathvalidate.validate_filepath(path, platform="windows")
            return True
        except pathvalidate.ValidationError:
            try:
                pathvalidate.validate_filepath(path, platform="posix")
                return True
            except pathvalidate.ValidationError:
                return False

        # Additional malware-specific path validation
        suspicious_indicators = [
            # Common malware paths
            r'\\temp\\[a-z0-9]{6,}\.(exe|dll|bat|scr)',
            r'/tmp/[a-z0-9]{6,}',
            r'%appdata%',
            r'%temp%',
            r'\\windows\\system32\\[a-z0-9]+\.(dll|exe)',
            # Persistence locations
            r'\\startup\\',
            r'\\autostart\\',
            r'/etc/init\.d/',
            r'/etc/cron',
        ]

        # Give bonus points for suspicious patterns (these are likely malicious paths)
        for pattern in suspicious_indicators:
            if re.search(pattern, path, re.IGNORECASE):
                return True

        return True

    except Exception:
        return False


def extract_processes(text: str) -> Set[str]:
    """Extract processes using LLM-based context analysis - placeholder for basic extraction."""
    # Minimal pattern matching as fallback - let LLM do the real work
    basic_patterns = [
        # Only clear executable references
        r'\b[a-zA-Z0-9_-]{3,30}\.exe\b',
    ]

    processes = set()

    for pattern in basic_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            process = match.strip()
            # Very basic filtering - let LLM handle the intelligence
            if len(process) > 6:  # Minimum .exe length
                processes.add(process)

    return processes


def extract_registry_keys(text: str) -> Set[str]:
    """Extract Windows registry keys and values with proper root key validation."""
    # Valid Windows registry root keys
    valid_root_keys = [
        'HKEY_CLASSES_ROOT', 'HKCR',
        'HKEY_CURRENT_USER', 'HKCU',
        'HKEY_LOCAL_MACHINE', 'HKLM',
        'HKEY_USERS', 'HKU',
        'HKEY_CURRENT_CONFIG', 'HKCC',
        'HKEY_PERFORMANCE_DATA',
        'HKEY_DYN_DATA'
    ]

    registry_patterns = [
        # Full registry paths with valid root keys
        r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\\]+(?:\\[^\\]+)*',
        # Registry key references
        r'\\Registry\\Machine\\[^\\]+(?:\\[^\\]+)*',
        # Common registry locations (must be preceded by valid root or context)
        r'(?:(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\)?(?:SOFTWARE|SYSTEM)\\[^\\]+(?:\\[^\\]+)*',
    ]

    registry_keys = set()

    for pattern in registry_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Clean up and validate the registry key
            key = match.strip()

            if _validate_registry_key(key, valid_root_keys):
                registry_keys.add(key)

    return registry_keys


def _validate_registry_key(key: str, valid_root_keys: list) -> bool:
    """Validate Windows registry key format and root keys."""
    try:
        # Basic length check
        if len(key) < 5 or len(key) > 1024:  # Reasonable registry key length limits
            return False

        # Skip if it contains obvious non-registry content
        if any(x in key.lower() for x in [
            'http', 'www', 'ftp://', '[.]', 'hxxp',
            'javascript:', 'mailto:', 'file://',
            # Command indicators that shouldn't be in registry keys
            'cmd.exe', 'powershell.exe', 'sc create', 'reg add',
            'net start', 'net stop', '&&', '||', ' & ',
            # Multi-line command indicators
            '\n', '\r\n', '; ', ' && ', ' || '
        ]):
            return False

        # Check for valid registry key characters (basic validation)
        if not re.match(r'^[A-Za-z0-9\\._\-{}\s:()]+$', key):
            return False

        # Extract the root key to validate
        key_upper = key.upper()

        # Handle \\Registry\\Machine\\ format (convert to HKLM format)
        if key_upper.startswith('\\REGISTRY\\MACHINE\\'):
            # This is a valid internal Windows registry path format
            return True

        # Check if it starts with a valid root key
        has_valid_root = False
        for root in valid_root_keys:
            if key_upper.startswith(root.upper() + '\\'):
                has_valid_root = True
                break

        # If no root key found, check if it might be a relative path under a common location
        if not has_valid_root:
            # Allow relative paths under SOFTWARE or SYSTEM if they look legitimate
            if (key_upper.startswith('SOFTWARE\\') or key_upper.startswith('SYSTEM\\')) and '\\' in key:
                return True
            return False

        # Additional validation: registry keys should have at least one subkey
        if key_upper.count('\\') < 1:
            return False

        # Check for suspicious patterns that indicate it's not a real registry key
        suspicious_patterns = [
            r'\\\\',  # Double backslashes (except at start)
            r'\\$',   # Ending with backslash
            r'\s+\\', # Space before backslash
            r'\\\s+', # Backslash followed by space
            # Command-like patterns
            r'\s+(create|add|delete|query|start|stop)\s+',
            r'(sc|net|reg)\s+',
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, key, re.IGNORECASE):
                return False

        return True

    except Exception:
        return False


def extract_commands(text: str) -> Set[str]:
    """Extract command line executions using LLM-based context analysis - placeholder for basic extraction."""
    # Minimal pattern matching as fallback - let LLM do the real work
    basic_patterns = [
        # Only very obvious command indicators - actual command line syntax
        r'(?:powershell|cmd)(?:\.exe)?\s+(?:-[a-zA-Z]+\s+|/[a-zA-Z]+\s+|&\s*|;|\$)[^\r\n]{10,}',  # Commands with flags/parameters
        r'-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}',  # Base64 encoded commands
        r'(?:sc|net|reg)\s+(?:create|add|start|stop|delete|query)\s+[^\r\n]{5,}',  # Service/registry commands
        r'(?:certutil|bitsadmin)\s+-[^\r\n]{10,}',  # Download tools with parameters
        r'wget\s+http[^\r\n\s]+',  # wget downloads
        r'curl\s+(?:-[a-zA-Z]\s+)*http[^\r\n\s]+',  # curl downloads
    ]

    commands = set()

    for pattern in basic_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            command = match.strip()
            # Filter out descriptive text - commands should not contain narrative language
            if (len(command) > 10 and
                not re.search(r'\b(?:has used|have used|uses|utilized|employs|leverages|executes)\b', command, re.IGNORECASE) and
                not re.search(r'\[[0-9]+\]', command) and  # Reference citations
                not command.startswith('PowerShell\t') and  # Tab-separated descriptive text
                not re.search(r'\b(?:APT\d+|threat actor|malware|campaign)\b', command, re.IGNORECASE)):
                commands.add(command)

    return commands


def extract_email_addresses(text: str) -> Set[str]:
    """Extract email addresses."""
    email_patterns = [
        # Standard email pattern
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        # Defanged emails
        r'\b[A-Za-z0-9._%+-]+\[@\][A-Za-z0-9.-]+\[\.\][A-Z|a-z]{2,}\b',
    ]

    emails = set()

    for pattern in email_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Normalize defanged emails
            email = match.replace('[@]', '@').replace('[.]', '.')
            emails.add(email.lower())

    return emails








def extract_url_candidates(text: str) -> set:
    """Extract URL candidates without LLM validation for batch processing."""
    url_patterns = [
        # Standard URLs
        r'https?://[^\s<>"]+',
        # Defanged URLs with hxxp
        r'hxxps?://[^\s<>"]+',
        # URLs with defanged protocols
        r'https?\[\:\]//[^\s<>"]+',
        # URLs with defanged domains
        r'https?://[^\s<>"]*\[?\.\]?[^\s<>"]*',
        # Defanged domains without protocol (with brackets) - ensure complete domain
        r'[a-zA-Z0-9.-]+\[\.\][a-zA-Z0-9.-]+\[\.\][a-zA-Z]{2,}(?:/[^\s<>"]*)?',
        # URLs without protocol (IP or domain with path)
        r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/[^\s<>"]+',
        # Login URLs without protocol
        r'\b[Ll]ogin[^\s<>"]*\.[a-zA-Z0-9.-]+(?:/[^\s<>"]*)?',
    ]

    urls = set()
    for pattern in url_patterns:
        # Don't use IGNORECASE for URL extraction to preserve case sensitivity
        matches = re.findall(pattern, text)
        for match in matches:
            # Clean up the URL
            original_url = match
            # Fix defanged URLs
            url = re.sub(r'hxxp', 'http', original_url, flags=re.IGNORECASE)
            url = re.sub(r'\[\:\]', ':', url)
            url = re.sub(r'\[\.\]', '.', url)

            # Add protocol if missing for domain-like patterns
            if not url.lower().startswith(('http://', 'https://')) and ('.' in url or '[' in original_url):
                # Check if it's likely a domain/URL
                if '/' in url or '?' in url or any(tld in url.lower() for tld in ['.com', '.org', '.net', '.gov']):
                    url = 'https://' + url

            # Basic cleanup
            url = url.rstrip('.,;:!?)')

            # Fix double slashes
            url = re.sub(r'(https?:)//+', r'\1//', url)

            # Basic filtering - exclude obviously false positives
            if any(exclude in url.lower() for exclude in ['example.com', 'test.com', 'localhost']):
                continue

            # Skip if it looks like a CIDR range that got mangled into a URL
            # Pattern: https://IP/CIDR or similar with trailing chars
            if re.match(r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}', url):
                continue

            # Skip URLs that are clearly CIDR ranges in disguise (after cleaning)
            # Check if removing protocol gives us a valid CIDR range
            url_without_protocol = re.sub(r'https?://', '', url)
            if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$', url_without_protocol):
                continue

            if len(url) > 10:  # Minimum reasonable URL length
                try:
                    canonical_url = canonicalize_url(url)
                    # Validate the canonicalized URL before adding
                    if _is_valid_url_format(canonical_url):
                        urls.add(canonical_url)
                except Exception:
                    # If canonicalization fails, try to add as-is if it looks valid
                    if url.startswith(('http://', 'https://')) and '.' in url and _is_valid_url_format(url):
                        urls.add(url)
                    continue

    return urls


def extract_domain_candidates(text: str) -> set:
    """Extract domain candidates without LLM validation for batch processing."""
    domain_patterns = [
        # Standard domains
        r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b',
        # Defanged domains
        r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\][a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\[\.\][a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b',
    ]

    domains = set()
    for pattern in domain_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            original_domain = match
            # Fix defanged domains
            domain = re.sub(r'\[\.\]', '.', original_domain)

            # Basic false positive filtering
            false_positives = {
                'e.g.', 'i.e.', 'etc.', 'vs.', 'no.', 'inc.', 'ltd.', 'corp.',
                '127.0.0.1', 'localhost', '0.0.0.0', '255.255.255.255'
            }
            if domain.lower() in false_positives:
                continue

            # Filter out Android package names (reverse DNS notation)
            if _is_android_package_name(domain):
                continue

            # Filter out file names with extensions
            if _looks_like_filename(domain):
                continue

            # Validate domain format using our custom validator
            if _is_valid_domain_format(domain) and len(domain) > 3:
                domains.add(normalize_domain(domain))

    return domains


def _is_android_package_name(domain: str) -> bool:
    """Check if a domain looks like an Android package name (reverse DNS)."""
    try:
        # Android package names typically follow reverse DNS: com.company.app
        # They usually have 3+ parts and start with common TLDs
        parts = domain.split('.')

        # Must have at least 3 parts
        if len(parts) < 3:
            return False

        # First part should be a common TLD used in reverse DNS
        common_tlds = {'com', 'org', 'net', 'de', 'eu', 'vpn', 'android'}
        if parts[0].lower() not in common_tlds:
            return False

        # Check for typical Android package patterns
        android_patterns = [
            'com.android.',
            'com.google.',
            'org.telegram.',
            'org.mozilla.',
            'org.thoughtcrime.',
            'net.openvpn.',
            'de.blinkt.',
            'eu.thedarken.',
            'vpn.fastvpn.'
        ]

        domain_lower = domain.lower()
        for pattern in android_patterns:
            if domain_lower.startswith(pattern):
                return True

        # Generic check: if it starts with com/org/net and has many parts, likely a package
        if parts[0].lower() in {'com', 'org', 'net'} and len(parts) >= 3:
            # Additional heuristic: check if it contains common app-related terms
            app_terms = {'app', 'apps', 'browser', 'messenger', 'providers', 'android', 'mobile', 'skydrive', 'dropbox'}
            domain_text = domain.lower().replace('.', ' ')
            if any(term in domain_text for term in app_terms):
                return True

            # Also check for typical company names in reverse DNS
            company_names = {'microsoft', 'google', 'facebook', 'amazon', 'apple', 'telegram', 'mozilla', 'skype'}
            if any(company in domain_text for company in company_names):
                return True

        return False

    except Exception:
        return False


def _looks_like_filename(domain: str) -> bool:
    """Check if a domain looks like a filename with extension using tldextract."""
    try:
        import tldextract

        # Check for common file extensions first
        file_extensions = {
            '.key', '.csv', '.db', '.sh', '.rc', '.cfg', '.conf', '.ini', '.log',
            '.cache', '.tmp', '.bak', '.xml', '.json', '.txt', '.dat', '.pid',
            '.flag', '.html', '.css', '.js', '.index', '.new', '.payload'
        }

        domain_lower = domain.lower()

        # Check if it ends with a known file extension
        for ext in file_extensions:
            if domain_lower.endswith(ext):
                return True

        # Use tldextract to check if this has a valid TLD
        if '.' in domain:
            try:
                extracted = tldextract.extract(domain)
                # If tldextract cannot find a valid suffix (TLD), it might be a filename
                if not extracted.suffix:
                    # No valid TLD found, likely a filename
                    return True

                # If it has only one part before the TLD and the TLD is very short,
                # it might still be a filename with a coincidental TLD-like extension
                if not extracted.subdomain and len(extracted.suffix) <= 3:
                    parts = domain.split('.')
                    if len(parts) == 2:
                        # Check if the first part looks like a filename
                        filename_part = parts[0].lower()
                        filename_indicators = ['session', 'android', 'cached', 'syscache', 'sysinfo', 'aid', 'ndata']
                        if any(indicator in filename_part for indicator in filename_indicators):
                            return True

            except Exception:
                # If tldextract fails, fall back to basic check
                pass

        return False

    except Exception:
        return False


def extract_ip_candidates(text: str) -> set:
    """Extract IP candidates without LLM validation for batch processing."""
    # First extract CIDR ranges to avoid duplicating the network portion
    cidr_patterns = [
        # IPv4 CIDR ranges
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/[0-9]{1,2}\b',
        # Defanged IPv4 CIDR ranges
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\]){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/[0-9]{1,2}\b',
    ]

    individual_ip_patterns = [
        # IPv4 addresses
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        # IPv6 addresses (simplified)
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{0,4}\b',
        # Defanged IPs
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\]){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    ]

    ips = set()
    found_cidrs = set()

    # First extract CIDR ranges
    for pattern in cidr_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Fix defanged CIDR ranges
            cidr = re.sub(r'\[\.\]', '.', match)

            if _is_valid_ip_format(cidr):
                # Store both the CIDR and the network portion for deduplication
                found_cidrs.add(cidr)
                network_ip = cidr.split('/')[0]
                found_cidrs.add(network_ip)  # Prevent extracting the network IP separately
                ips.add(cidr)

    # Then extract individual IPs, but skip ones already found as CIDR networks
    for pattern in individual_ip_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            original_ip = match
            # Fix defanged IPs
            ip = re.sub(r'\[\.\]', '.', match)

            # Skip if this IP is already part of a CIDR range we found
            if ip in found_cidrs:
                continue

            # Skip private/reserved ranges unless defanged (which indicates threat context)
            private_patterns = [
                r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.', r'^127\.',
                r'^169\.254\.', r'^224\.', r'^0\.', r'^255\.255\.255\.255$'
            ]

            is_private = any(re.match(pattern, ip) for pattern in private_patterns)

            # If defanged, include regardless of being private
            if '[.]' in original_ip:
                is_private = False

            # For private IPs, do basic threat context check
            if is_private:
                context_window = 100
                ip_pos = text.find(match)
                if ip_pos != -1:
                    context = text[max(0, ip_pos-context_window):ip_pos+len(match)+context_window].lower()
                    threat_context = any(word in context for word in [
                        'malware', 'c2', 'command', 'control', 'beacon', 'callback',
                        'threat', 'attack', 'compromise', 'infrastructure'
                    ])
                    if not threat_context:
                        continue

            # Validate IP format using our custom validator
            if _is_valid_ip_format(ip):
                # Additional check: exclude values that look like certificate serials or MAC addresses
                # even if they technically pass IPv6 validation
                parts = ip.split(':')

                # Skip if it looks like SSL certificate serial (8 groups of 1-4 hex chars, no double colon)
                if (len(parts) == 8 and
                    all(len(part) <= 4 and all(c in '0123456789abcdefABCDEF' for c in part) for part in parts) and
                    '::' not in ip):
                    logger.info(f"Excluded certificate serial-like pattern from IP extraction: {ip}")
                    continue

                # Skip if it looks like MAC address (6 groups of exactly 2 hex chars)
                if (len(parts) == 6 and
                    all(len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part) for part in parts)):
                    logger.info(f"Excluded MAC address-like pattern from IP extraction: {ip}")
                    continue

                ips.add(normalize_ip(ip))

    return ips


def extract_and_normalize(input_data: IOCInput) -> IOCOutput:
    """Extract and normalize IOCs from text using pattern matching and validation."""
    try:
        text = input_data.text
        metadata = input_data.metadata

        # First extract IOCs from STIX patterns if present
        stix_iocs = extract_stix_patterns(text)
        excluded_values = stix_iocs.get('excluded_values', set())

        # Extract different types of IOCs using regular patterns, excluding STIX-processed values
        urls_raw = extract_url_candidates(text)
        urls = [url for url in urls_raw if url not in excluded_values]

        domains_raw = extract_domain_candidates(text)
        domains = [domain for domain in domains_raw if domain not in excluded_values]

        ips_raw = extract_ip_candidates(text)
        # Filter out values that were already processed by STIX patterns (like certificate serials)
        ips_filtered = {ip for ip in ips_raw if ip not in excluded_values}

        # Filter IPs into routable and non-routable
        routable_ips, non_routable_ips = filter_routable_ips(ips_filtered)
        ips = list(routable_ips)

        hashes_raw = extract_hashes(text)
        hashes = [hash_val for hash_val in hashes_raw if hash_val not in excluded_values]

        # Add STIX-extracted IOCs
        urls.extend(list(stix_iocs['urls']))
        domains.extend(list(stix_iocs['domains']))

        # Apply validators library filtering before LLM processing for better efficiency
        logger.debug(f"Before validators filtering: {len(urls)} URLs, {len(domains)} domains, {len(ips)} IPs")
        urls = _filter_iocs_with_validators(urls, "url")
        domains = _filter_iocs_with_validators(domains, "domain")
        ips = _filter_iocs_with_validators(ips, "ip")
        logger.debug(f"After validators filtering: {len(urls)} URLs, {len(domains)} domains, {len(ips)} IPs")
        ips.extend(list(stix_iocs['ips']))
        hashes.extend(list(stix_iocs['hashes']))

        # Deduplicate combined results
        urls = list(set(urls))
        domains = list(set(domains))
        ips = list(set(ips))
        hashes = list(set(hashes))
        file_paths = list(extract_file_paths(text))
        processes = list(extract_processes(text))
        registry_keys = list(extract_registry_keys(text))
        commands = list(extract_commands(text))
        email_addresses = list(extract_email_addresses(text))

        # Use batch validation for better performance if we have many IOCs
        if len(urls + domains + ips) > 10:
            validation_result = _batch_validate_iocs_with_llm(urls, domains, ips, text, metadata)

            # Filter based on LLM validation
            validated_urls = [url for url, result in validation_result.get("urls", {}).items() if result.get("malicious", True)]
            validated_domains = [domain for domain, result in validation_result.get("domains", {}).items() if result.get("malicious", True)]
            validated_ips = [ip for ip, result in validation_result.get("ips", {}).items() if result.get("malicious", True)]

            urls = validated_urls
            domains = validated_domains
            ips = validated_ips

        return IOCOutput(
            urls=urls,
            domains=domains,
            ips=ips,
            hashes=hashes,
            file_paths=file_paths,
            processes=processes,
            registry_keys=registry_keys,
            commands=commands,
            email_addresses=email_addresses,
            non_routable_ips=non_routable_ips
        )
    except Exception as e:
        logger.error(f"Error extracting IOCs: {e}")
        return IOCOutput()


# Tool registration for MCP
TOOL_NAME = "ioc.extract_and_normalize"
TOOL_DESCRIPTION = "Extract and normalize IOCs from text"
INPUT_SCHEMA = IOCInput.model_json_schema()
OUTPUT_SCHEMA = IOCOutput.model_json_schema()