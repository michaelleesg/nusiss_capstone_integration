"""Tool proxy for accessing tools via MCP or direct imports."""

import logging
from typing import Any, Dict

from .config import get_mcp_config

logger = logging.getLogger(__name__)


class ToolProxy:
    """Proxy for accessing tools with MCP fallback to direct imports."""

    def __init__(self, use_mcp: bool = True, mcp_config=None):
        """Initialize tool proxy.

        Args:
            use_mcp: Whether to try MCP first. Falls back to direct imports if MCP fails.
            mcp_config: MCP configuration object. If None, loads from environment.
        """
        self.use_mcp = use_mcp
        self.mcp_config = mcp_config or get_mcp_config()
        self._mcp_available = None
        self._mcp_client = None

    def _get_mcp_client(self):
        """Get MCP client with lazy initialization."""
        if self._mcp_client is None:
            try:
                from .mcp_client import MCPClient
                self._mcp_client = MCPClient(
                    use_tcp=self.mcp_config.use_tcp,
                    host=self.mcp_config.host,
                    port=self.mcp_config.port,
                    start_server=self.mcp_config.start_server
                )
                self._mcp_client.start()
                self._mcp_available = True
                if self.mcp_config.start_server:
                    logger.info(f"MCP client initialized successfully ({self.mcp_config})")
                else:
                    logger.info(f"MCP client connected to existing server ({self.mcp_config})")
            except Exception as e:
                logger.warning(f"MCP client initialization failed: {e}")
                self._mcp_available = False
                self._mcp_client = None
        return self._mcp_client

    def call_tool(self, tool_name: str, **kwargs) -> Any:
        """Call a tool by name with keyword arguments.

        Args:
            tool_name: Name of the tool to call
            **kwargs: Tool arguments

        Returns:
            Tool result
        """
        # Try MCP first if enabled
        if self.use_mcp and self._mcp_available != False:
            try:
                client = self._get_mcp_client()
                if client:
                    result = client.call_tool(tool_name, kwargs)
                    logger.debug(f"Tool {tool_name} called via MCP")
                    return result
            except Exception as e:
                logger.warning(f"MCP call for {tool_name} failed: {e}, falling back to direct import")
                self._mcp_available = False

        # Fallback to direct import
        return self._call_direct(tool_name, **kwargs)

    def _call_direct(self, tool_name: str, **kwargs) -> Any:
        """Call tool via direct import."""
        logger.debug(f"Tool {tool_name} called via direct import")

        # Map tool names to their direct import paths and functions
        tool_map = {
            # Core tools
            "http_fetch": ("app.tools.http_fetch", "http_fetch", "HttpFetchInput"),
            "detect_kind": ("app.tools.detect_kind", "detect_kind", "DetectInput"),

            # Parsers
            "misp_parse_event": ("app.tools.parsers.misp_parse", "misp_parse_event", "MISPParseInput"),
            "stix_parse_bundle": ("app.tools.parsers.stix_parse", "stix_parse_bundle", "STIXParseInput"),
            "rss_parse": ("app.tools.parsers.rss_parse", "rss_parse", "RSSParseInput"),
            "html_to_markdown": ("app.tools.parsers.html_to_markdown", "html_to_markdown", "HTMLToMarkdownInput"),
            "pdf_to_text": ("app.tools.parsers.pdf_to_text", "pdf_to_text", "PDFToTextInput"),
            "json_normalize": ("app.tools.parsers.json_normalize", "json_normalize", "JSONNormalizeInput"),

            # Analysis tools
            "extract_pdf_text_and_markup": ("app.tools.pdf_extract", "extract_pdf_text_and_markup", "PDFExtractInput"),
            "summarize_threat": ("app.tools.nlp", "summarize_threat", "ThreatSummaryInput"),
            "extract_entities": ("app.tools.nlp", "extract_entities", "EntityExtractionInput"),
            "classify_geo_scope": ("app.tools.nlp", "classify_geo_scope", "GeoScopeInput"),
            "classify_high_tension": ("app.tools.nlp", "classify_high_tension", "HighTensionInput"),
            "classify_motivation": ("app.tools.nlp", "classify_motivation", "MotivationInput"),
            "is_cyber_related": ("app.tools.nlp", "is_cyber_related", "CyberClassificationInput"),

            # Processing tools
            "extract_and_normalize": ("app.tools.ioc", "extract_and_normalize", "IOCExtractionInput"),
            "extract_from_text": ("app.tools.cve", "extract_from_text", "CVEExtractionInput"),
            "enrich": ("app.tools.cve", "enrich", "CVEEnrichInput"),
            "classify_ip_addresses": ("app.tools.ip_classifier", "classify_ip_addresses", "IPClassificationInput"),
            "validate_and_heal": ("app.tools.schema_validate", "validate_and_heal", "SchemaInput"),
            "store_emit": ("app.tools.store_emit", "store_emit", "StoreEmitInput"),
        }

        if tool_name not in tool_map:
            raise ValueError(f"Unknown tool: {tool_name}")

        module_name, func_name, input_class_name = tool_map[tool_name]

        try:
            # Import the module
            import importlib
            module = importlib.import_module(module_name)

            # Get the function and input class
            func = getattr(module, func_name)
            input_class = getattr(module, input_class_name)

            # Create input object and call function
            input_obj = input_class(**kwargs)
            result = func(input_obj)

            # Convert result to dict if it's a Pydantic model
            if hasattr(result, "model_dump"):
                return result.model_dump()
            elif hasattr(result, "dict"):
                return result.dict()
            else:
                return result

        except Exception as e:
            logger.error(f"Direct tool call failed for {tool_name}: {e}")
            raise

    def cleanup(self):
        """Clean up resources."""
        if self._mcp_client:
            try:
                self._mcp_client.stop()
            except Exception as e:
                logger.warning(f"Error stopping MCP client: {e}")
            self._mcp_client = None


# Global tool proxy instance
_tool_proxy = None


def get_tool_proxy(mcp_config=None) -> ToolProxy:
    """Get global tool proxy instance."""
    global _tool_proxy
    if _tool_proxy is None:
        _tool_proxy = ToolProxy(use_mcp=True, mcp_config=mcp_config)
    return _tool_proxy


def call_tool(tool_name: str, **kwargs) -> Any:
    """Convenience function to call a tool."""
    proxy = get_tool_proxy()
    return proxy.call_tool(tool_name, **kwargs)


def cleanup_tool_proxy():
    """Clean up global tool proxy."""
    global _tool_proxy
    if _tool_proxy:
        _tool_proxy.cleanup()
        _tool_proxy = None