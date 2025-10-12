"""Canonicalization and deduplication utilities."""

import re
import hashlib
from typing import List, Set, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import tldextract
import validators


def canonicalize_url(url: str) -> str:
    """Canonicalize URL for deduplication while preserving case-sensitive parts."""
    try:
        # Parse URL without lowercasing to preserve path/query/fragment case
        parsed = urlparse(url.strip())

        # Normalize scheme (case insensitive)
        scheme = (parsed.scheme or "https").lower()
        if scheme not in ("http", "https"):
            scheme = "https"

        # Normalize netloc (case insensitive for domains)
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]

        # Remove default ports
        if scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        elif scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]

        # Preserve path case but normalize trailing slashes
        path = parsed.path or "/"
        if path.endswith("/") and len(path) > 1:
            path = path[:-1]

        # Remove tracking parameters from Google, Facebook, Mailchimp and other analytics platform
        # NOTE: user_code is NOT a tracking parameter - it's part of malicious IOC URLs
        tracking_params = {
            "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
            "gclid", "fbclid", "ref", "_ga", "_gl", "mc_eid", "mc_cid"
        }

        # Sort and filter query parameters (preserve case in values)
        if parsed.query:
            query_dict = parse_qs(parsed.query)
            filtered_params = {
                k: v for k, v in query_dict.items()
                if k.lower() not in tracking_params
            }
            query = urlencode(sorted(filtered_params.items()), doseq=True)
        else:
            query = ""

        # Preserve fragment case (fragments can be case-sensitive)
        fragment = parsed.fragment or ""
        return urlunparse((scheme, netloc, path, parsed.params, query, fragment))

    except Exception:
        # Fallback: return original URL to preserve case
        return url


def normalize_domain(domain: str) -> str:
    """Normalize domain for deduplication."""
    try:
        domain = domain.lower().strip()

        # Remove leading/trailing dots
        domain = domain.strip(".")

        # Convert to punycode if needed
        try:
            domain = domain.encode("ascii").decode("ascii")
        except UnicodeDecodeError:
            domain = domain.encode("idna").decode("ascii")

        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]

        return domain
    except Exception:
        return domain.lower()


def normalize_ip(ip: str) -> str:
    """Normalize IP address."""
    ip = ip.strip()

    # IPv4 normalization (remove leading zeros)
    if validators.ipv4(ip):
        parts = ip.split(".")
        normalized_parts = [str(int(part)) for part in parts]
        return ".".join(normalized_parts)

    # IPv6 normalization (basic)
    if validators.ipv6(ip):
        # Remove leading zeros and compress
        try:
            from ipaddress import ip_address
            return str(ip_address(ip))
        except Exception:
            pass

    return ip


def normalize_hash(hash_value: str) -> str:
    """Normalize hash value."""
    hash_value = hash_value.lower().strip()

    # Validate hash length
    if len(hash_value) in (32, 40, 64, 128):  # MD5, SHA1, SHA256, SHA512
        return hash_value

    return hash_value


def normalize_cve(cve: str) -> str:
    """Normalize CVE identifier."""
    cve = cve.upper().strip()

    # Ensure CVE format
    if not cve.startswith("CVE-"):
        cve = f"CVE-{cve}"

    # Validate basic format
    if re.match(r"CVE-\d{4}-\d{4,}", cve):
        return cve

    return cve


def merge_and_dedup_lists(lists: List[List[str]]) -> List[str]:
    """Merge multiple lists and remove duplicates while preserving order."""
    seen: Set[str] = set()
    result: List[str] = []

    for lst in lists:
        for item in lst:
            if item and item not in seen:
                seen.add(item)
                result.append(item)

    return result


def merge_iocs(ioc_dicts: List[Dict[str, List[str]]]) -> Dict[str, List[str]]:
    """Merge IOC dictionaries with normalization."""
    merged = {
        "urls": [],
        "domains": [],
        "hashes": [],
        "ips": []
    }

    all_urls = []
    all_domains = []
    all_hashes = []
    all_ips = []

    for ioc_dict in ioc_dicts:
        all_urls.extend(ioc_dict.get("urls", []))
        all_domains.extend(ioc_dict.get("domains", []))
        all_hashes.extend(ioc_dict.get("hashes", []))
        all_ips.extend(ioc_dict.get("ips", []))

    # Normalize and deduplicate
    seen_urls: Set[str] = set()
    for url in all_urls:
        canonical = canonicalize_url(url)
        if canonical not in seen_urls:
            seen_urls.add(canonical)
            merged["urls"].append(canonical)

    seen_domains: Set[str] = set()
    for domain in all_domains:
        normalized = normalize_domain(domain)
        if normalized not in seen_domains:
            seen_domains.add(normalized)
            merged["domains"].append(normalized)

    seen_hashes: Set[str] = set()
    for hash_val in all_hashes:
        normalized = normalize_hash(hash_val)
        if normalized not in seen_hashes and len(normalized) in (32, 40, 64, 128):
            seen_hashes.add(normalized)
            merged["hashes"].append(normalized)

    seen_ips: Set[str] = set()
    for ip in all_ips:
        normalized = normalize_ip(ip)
        if normalized not in seen_ips:
            seen_ips.add(normalized)
            merged["ips"].append(normalized)

    return merged


def compute_content_hash(content: bytes) -> str:
    """Compute SHA-256 hash of content."""
    return hashlib.sha256(content).hexdigest()