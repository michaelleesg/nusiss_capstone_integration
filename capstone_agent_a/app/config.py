"""Configuration management for the CTI application."""

import os
from typing import Optional
from dotenv import load_dotenv


class MCPConfig:
    """MCP server configuration."""

    def __init__(self):
        """Initialize MCP configuration from environment variables."""
        # Load environment variables
        load_dotenv()

        # MCP transport configuration
        self.transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
        self.host = os.getenv("MCP_HOST", "127.0.0.1")
        self.port = int(os.getenv("MCP_PORT", "8765"))

        # Whether to start server automatically or connect to existing one
        self.start_server = os.getenv("MCP_START_SERVER", "true").lower() == "true"

    @property
    def use_tcp(self) -> bool:
        """Whether to use TCP transport."""
        return self.transport == "tcp"

    def get_server_args(self) -> list[str]:
        """Get server command arguments."""
        if self.use_tcp:
            return [
                "--transport", "tcp",
                "--host", self.host,
                "--port", str(self.port)
            ]
        return []

    def __str__(self) -> str:
        """String representation of configuration."""
        if self.use_tcp:
            return f"TCP({self.host}:{self.port})"
        return "stdio"


# Global configuration instance
_mcp_config: Optional[MCPConfig] = None


def get_mcp_config() -> MCPConfig:
    """Get global MCP configuration instance."""
    global _mcp_config
    if _mcp_config is None:
        _mcp_config = MCPConfig()
    return _mcp_config


def reload_mcp_config() -> MCPConfig:
    """Reload MCP configuration from environment."""
    global _mcp_config
    _mcp_config = MCPConfig()
    return _mcp_config