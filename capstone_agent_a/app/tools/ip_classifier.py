"""IP address classification tool for determining routable vs non-routable addresses."""

import ipaddress
import logging
from typing import Dict, List, Tuple
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class IPClassificationInput(BaseModel):
    """Input for IP address classification."""

    ips: List[str] = Field(description="List of IP addresses to classify")


class IPClassificationResult(BaseModel):
    """Result for a single IP classification."""

    ip: str = Field(description="The IP address")
    is_routable: bool = Field(description="Whether the IP is globally routable")
    reason: str = Field(description="Reason for classification")
    ip_type: str = Field(description="Type of IP address")


class IPClassificationOutput(BaseModel):
    """Output for IP address classification."""

    routable: List[str] = Field(description="Globally routable IP addresses")
    non_routable: List[IPClassificationResult] = Field(description="Non-routable IP addresses with reasons")


def classify_ipv4(ip_str: str) -> Tuple[bool, str, str]:
    """
    Classify an IPv4 address as routable or non-routable.

    Returns:
        Tuple of (is_routable, reason, ip_type)
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)

        # Check non-routable IPv4 blocks

        # RFC 1918 Private addresses
        if ip in ipaddress.IPv4Network('10.0.0.0/8'):
            return False, "RFC 1918 private address space", "Private"
        elif ip in ipaddress.IPv4Network('172.16.0.0/12'):
            return False, "RFC 1918 private address space", "Private"
        elif ip in ipaddress.IPv4Network('192.168.0.0/16'):
            return False, "RFC 1918 private address space", "Private"

        # Carrier-Grade NAT (RFC 6598)
        elif ip in ipaddress.IPv4Network('100.64.0.0/10'):
            return False, "Carrier-Grade NAT address space (RFC 6598)", "Shared"

        # Loopback
        elif ip in ipaddress.IPv4Network('127.0.0.0/8'):
            return False, "Loopback address space", "Loopback"

        # Link-local / APIPA
        elif ip in ipaddress.IPv4Network('169.254.0.0/16'):
            return False, "Link-local/APIPA address space", "Link-local"

        # Documentation/Test networks
        elif ip in ipaddress.IPv4Network('192.0.2.0/24'):
            return False, "TEST-NET-1 documentation address space", "Documentation"
        elif ip in ipaddress.IPv4Network('198.51.100.0/24'):
            return False, "TEST-NET-2 documentation address space", "Documentation"
        elif ip in ipaddress.IPv4Network('203.0.113.0/24'):
            return False, "TEST-NET-3 documentation address space", "Documentation"

        # "This network" / source address special use
        elif ip in ipaddress.IPv4Network('0.0.0.0/8'):
            return False, "Special use address space (this network)", "Special"

        # Multicast
        elif ip in ipaddress.IPv4Network('224.0.0.0/4'):
            return False, "Multicast address space", "Multicast"

        # Reserved / future use
        elif ip in ipaddress.IPv4Network('240.0.0.0/4'):
            return False, "Reserved/future use address space", "Reserved"

        # Limited broadcast
        elif ip == ipaddress.IPv4Address('255.255.255.255'):
            return False, "Limited broadcast address", "Broadcast"

        # If none of the above, it's globally routable
        else:
            return True, "Globally routable public address", "Public"

    except ipaddress.AddressValueError:
        return False, "Invalid IPv4 address format", "Invalid"


def classify_ipv6(ip_str: str) -> Tuple[bool, str, str]:
    """
    Classify an IPv6 address as routable or non-routable.

    Returns:
        Tuple of (is_routable, reason, ip_type)
    """
    try:
        ip = ipaddress.IPv6Address(ip_str)

        # Check non-routable IPv6 blocks

        # Loopback
        if ip == ipaddress.IPv6Address('::1'):
            return False, "IPv6 loopback address", "Loopback"

        # Link-local
        elif ip in ipaddress.IPv6Network('fe80::/10'):
            return False, "IPv6 link-local address space", "Link-local"

        # Unique Local Addresses (ULA) - IPv6 equivalent of private
        elif ip in ipaddress.IPv6Network('fc00::/7'):
            return False, "IPv6 Unique Local Address (ULA) space", "Private"

        # Unspecified address
        elif ip == ipaddress.IPv6Address('::'):
            return False, "IPv6 unspecified address", "Special"

        # Multicast
        elif ip in ipaddress.IPv6Network('ff00::/8'):
            return False, "IPv6 multicast address space", "Multicast"

        # Documentation
        elif ip in ipaddress.IPv6Network('2001:db8::/32'):
            return False, "IPv6 documentation address space", "Documentation"

        # IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        elif ip.ipv4_mapped:
            # Extract the IPv4 part and classify it
            ipv4_part = ip.ipv4_mapped
            is_routable, reason, _ = classify_ipv4(str(ipv4_part))
            if not is_routable:
                return False, f"IPv4-mapped IPv6 with non-routable IPv4: {reason}", "IPv4-mapped"
            else:
                return True, "IPv4-mapped IPv6 with routable IPv4 address", "IPv4-mapped"

        # If none of the above, it's globally routable
        else:
            return True, "Globally routable IPv6 address", "Public"

    except ipaddress.AddressValueError:
        return False, "Invalid IPv6 address format", "Invalid"


def classify_ip_address(ip_str: str) -> Tuple[bool, str, str]:
    """
    Classify an IP address (IPv4 or IPv6) or CIDR range as routable or non-routable.

    Returns:
        Tuple of (is_routable, reason, ip_type)
    """
    ip_str = ip_str.strip()

    # Check if it's a CIDR range first
    if '/' in ip_str:
        try:
            network = ipaddress.ip_network(ip_str, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                # For CIDR ranges, classify the network address
                network_ip = str(network.network_address)
                return classify_ipv4(network_ip)
            elif isinstance(network, ipaddress.IPv6Network):
                network_ip = str(network.network_address)
                return classify_ipv6(network_ip)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            pass

    # Try IPv4 individual address
    try:
        ipaddress.IPv4Address(ip_str)
        return classify_ipv4(ip_str)
    except ipaddress.AddressValueError:
        pass

    # Try IPv6 individual address
    try:
        ipaddress.IPv6Address(ip_str)
        return classify_ipv6(ip_str)
    except ipaddress.AddressValueError:
        pass

    # Not a valid IP address or network
    return False, "Invalid IP address format", "Invalid"


def classify_ip_addresses(input_data: IPClassificationInput) -> IPClassificationOutput:
    """
    Classify multiple IP addresses as routable or non-routable.
    """
    routable = []
    non_routable = []

    for ip_str in input_data.ips:
        is_routable, reason, ip_type = classify_ip_address(ip_str)

        if is_routable:
            routable.append(ip_str)
        else:
            non_routable.append(IPClassificationResult(
                ip=ip_str,
                is_routable=False,
                reason=reason,
                ip_type=ip_type
            ))

    logger.info(f"Classified {len(input_data.ips)} IPs: {len(routable)} routable, {len(non_routable)} non-routable")

    return IPClassificationOutput(
        routable=routable,
        non_routable=non_routable
    )


# Tool registration for MCP
TOOL_NAME = "ip_classifier.classify_ip_addresses"
TOOL_DESCRIPTION = "Classify IP addresses as globally routable or non-routable"
INPUT_SCHEMA = IPClassificationInput.model_json_schema()
OUTPUT_SCHEMA = IPClassificationOutput.model_json_schema()