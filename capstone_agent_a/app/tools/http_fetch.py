"""HTTP fetch tool with content detection."""

import base64
import logging
import mimetypes
from typing import Optional
from urllib.parse import urlparse

import httpx
import magic
from pydantic import BaseModel, Field, ValidationError

from ..dedup import compute_content_hash

logger = logging.getLogger(__name__)


class HttpFetchInput(BaseModel):
    """Input for HTTP fetch tool."""

    url: str = Field(description="URL to fetch")
    timeout_s: int = Field(default=20, description="Request timeout in seconds")
    max_bytes: int = Field(default=5_000_000, description="Maximum content size in bytes")
    username: Optional[str] = Field(default=None, description="Username for HTTP basic authentication")
    password: Optional[str] = Field(default=None, description="Password for HTTP basic authentication")
    verify_ssl: bool = Field(default=True, description="Whether to verify SSL certificates")


class HttpFetchOutput(BaseModel):
    """Output for HTTP fetch tool."""

    status: int = Field(description="HTTP status code")
    headers: dict = Field(description="Response headers")
    mime: str = Field(description="MIME type")
    content_b64: str = Field(description="Base64-encoded content")
    sha256: str = Field(description="SHA-256 hash of content")


def detect_mime_type(content: bytes, url: str, content_type: Optional[str] = None) -> str:
    """Detect MIME type from content and headers."""
    try:
        # First try python-magic for accurate detection
        try:
            mime = magic.from_buffer(content, mime=True)
            if mime and mime != "application/octet-stream":
                return mime
        except Exception as e:
            logger.debug(f"Magic detection failed: {e}")

        # Fall back to content-type header
        if content_type:
            # Extract primary mime type (ignore charset etc.)
            mime = content_type.split(";")[0].strip().lower()
            if mime:
                return mime

        # Fall back to URL extension
        parsed = urlparse(url)
        if parsed.path:
            mime, _ = mimetypes.guess_type(parsed.path)
            if mime:
                return mime

        # Default fallback
        if content.startswith(b"<!DOCTYPE") or content.startswith(b"<html"):
            return "text/html"
        elif content.startswith(b"%PDF"):
            return "application/pdf"
        elif content.startswith(b"{") or content.startswith(b"["):
            return "application/json"
        elif content.startswith(b"<?xml"):
            return "application/xml"
        else:
            return "text/plain"

    except Exception as e:
        logger.warning(f"MIME detection failed: {e}")
        return "application/octet-stream"


def http_fetch(input_data: HttpFetchInput) -> HttpFetchOutput:
    """Fetch URL and return content with metadata."""
    try:
        # Outer try-catch to handle any ValidationError that might escape
        return _http_fetch_internal(input_data)
    except ValidationError as e:
        logger.error(f"Pydantic ValidationError in http_fetch: {e}")
        raise RuntimeError(f"Validation error: {str(e)}")
    except Exception as e:
        # Re-raise other exceptions as-is
        raise


def _http_fetch_internal(input_data: HttpFetchInput) -> HttpFetchOutput:
    """Internal HTTP fetch implementation."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CTI-Agent/1.0)",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }

        # Setup authentication if provided
        auth = None
        if input_data.username and input_data.password:
            auth = httpx.BasicAuth(input_data.username, input_data.password)
            logger.info(f"Using HTTP basic auth for user: {input_data.username}")

        # Log SSL verification status for security awareness
        if not input_data.verify_ssl:
            logger.warning("SSL certificate verification disabled - this is insecure")

        with httpx.Client(timeout=input_data.timeout_s, follow_redirects=True, auth=auth, verify=input_data.verify_ssl) as client:
            logger.info(f"Fetching URL: {input_data.url}")

            response = client.get(input_data.url, headers=headers)
            response.raise_for_status()

            # Check content size
            content = response.content
            if len(content) > input_data.max_bytes:
                logger.warning(f"Content too large: {len(content)} bytes, truncating")
                content = content[:input_data.max_bytes]

            # Detect MIME type
            content_type = response.headers.get("content-type")
            mime_type = detect_mime_type(content, input_data.url, content_type)

            # Compute hash and encode content
            content_hash = compute_content_hash(content)
            content_b64 = base64.b64encode(content).decode("ascii")

            logger.info(
                f"Fetched {len(content)} bytes, MIME: {mime_type}, "
                f"SHA-256: {content_hash[:16]}..."
            )

            return HttpFetchOutput(
                status=response.status_code,
                headers=dict(response.headers),
                mime=mime_type,
                content_b64=content_b64,
                sha256=content_hash
            )

    except httpx.TimeoutException:
        logger.error(f"Timeout fetching {input_data.url}")
        raise RuntimeError("Request timeout")
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error {e.response.status_code} fetching {input_data.url}")
        raise RuntimeError(f"HTTP {e.response.status_code}")
    except Exception as e:
        logger.error(f"Error fetching {input_data.url}: {e}")
        raise RuntimeError(f"Fetch error: {str(e)}")


# Tool registration for MCP
TOOL_NAME = "http.fetch_url"
TOOL_DESCRIPTION = "Fetch URL and return content with metadata"
INPUT_SCHEMA = HttpFetchInput.model_json_schema()
OUTPUT_SCHEMA = HttpFetchOutput.model_json_schema()