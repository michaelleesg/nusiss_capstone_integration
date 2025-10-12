"""MCP server with configurable JSON-RPC transport."""

import argparse
import json
import logging
import sys
import time
from typing import Any, Dict, Optional

from .schemas import get_all_tools, call_tool
from .transport_stdio import StdioTransport
from .transport_tcp import TcpTransport
from ..logging_conf import setup_logging

logger = logging.getLogger(__name__)


class MCPServer:
    """MCP server for CTI tools."""

    def __init__(self, transport_type: str = "stdio", host: str = "127.0.0.1", port: int = 8765):
        """Initialize MCP server with specified transport.

        Args:
            transport_type: Transport type ("stdio" or "tcp")
            host: IP address for TCP transport
            port: Port for TCP transport
        """
        if transport_type == "tcp":
            self.transport = TcpTransport(host, port)
        else:
            self.transport = StdioTransport()

        self.transport_type = transport_type
        self.tools = {}
        self._load_tools()

    def _load_tools(self) -> None:
        """Load all available tools."""
        try:
            all_tools = get_all_tools()
            for tool in all_tools:
                self.tools[tool["name"]] = tool
            logger.info(f"Loaded {len(self.tools)} tools")
        except Exception as e:
            logger.error(f"Error loading tools: {e}")

    def handle_tools_list(self, request_id: Any, params: Optional[Dict] = None) -> None:
        """Handle tools/list request."""
        try:
            start_time = time.time()

            # Return list of tool descriptors
            tools_list = []
            for tool_name, tool_config in self.tools.items():
                tools_list.append({
                    "name": tool_name,
                    "description": tool_config["description"],
                    "input_schema": tool_config["input_schema"],
                    "output_schema": tool_config["output_schema"]
                })

            duration = time.time() - start_time
            logger.info(f"tools/list completed in {duration:.3f}s, returned {len(tools_list)} tools")

            self.transport.send_response(request_id, {"tools": tools_list})

        except Exception as e:
            logger.error(f"Error in tools/list: {e}")
            self.transport.send_error(
                request_id,
                -32603,  # Internal error
                f"Internal error: {str(e)}"
            )

    def handle_tools_call(self, request_id: Any, params: Dict[str, Any]) -> None:
        """Handle tools/call request."""
        try:
            start_time = time.time()

            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if not tool_name:
                self.transport.send_error(
                    request_id,
                    -32602,  # Invalid params
                    "Missing required parameter: name"
                )
                return

            if tool_name not in self.tools:
                self.transport.send_error(
                    request_id,
                    -32601,  # Method not found
                    f"Tool not found: {tool_name}"
                )
                return

            logger.info(f"Calling tool: {tool_name}")
            logger.debug(f"Arguments: {arguments}")

            # Call the tool
            result = call_tool(tool_name, arguments)

            duration = time.time() - start_time
            result_size = len(json.dumps(result)) if result else 0
            logger.info(f"tools/call {tool_name} completed in {duration:.3f}s, {result_size} bytes")

            self.transport.send_response(request_id, {"result": result})

        except ValueError as e:
            logger.warning(f"Validation error in tools/call: {e}")
            self.transport.send_error(
                request_id,
                -32602,  # Invalid params
                f"Validation error: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Error in tools/call: {e}")
            self.transport.send_error(
                request_id,
                -32603,  # Internal error
                f"Internal error: {str(e)}"
            )

    def handle_request(self, message: Dict[str, Any]) -> None:
        """Handle incoming JSON-RPC request."""
        try:
            jsonrpc = message.get("jsonrpc")
            if jsonrpc != "2.0":
                logger.warning(f"Invalid JSON-RPC version: {jsonrpc}")
                return

            method = message.get("method")
            params = message.get("params")
            request_id = message.get("id")

            if method == "tools/list":
                self.handle_tools_list(request_id, params)
            elif method == "tools/call":
                self.handle_tools_call(request_id, params)
            else:
                self.transport.send_error(
                    request_id,
                    -32601,  # Method not found
                    f"Unknown method: {method}"
                )

        except Exception as e:
            logger.error(f"Error handling request: {e}")
            request_id = message.get("id")
            self.transport.send_error(
                request_id,
                -32603,  # Internal error
                f"Request handling error: {str(e)}"
            )

    def run(self) -> None:
        """Run the MCP server."""
        if self.transport_type == "tcp":
            logger.info(f"Starting MCP server (TCP on {self.transport.host}:{self.transport.port})")
            self.transport.start_server()
            self._run_tcp_server()
        else:
            logger.info("Starting MCP server (stdio)")
            self._run_stdio_server()

    def _run_tcp_server(self) -> None:
        """Run TCP server with multiple client support."""
        try:
            while True:
                # Wait for client connection
                if not self.transport.accept_client():
                    break

                # Handle this client's requests
                try:
                    while True:
                        message = self.transport.read_message()
                        if message is None:
                            logger.info("Client disconnected, waiting for next client...")
                            break
                        self.handle_request(message)
                except Exception as e:
                    logger.error(f"Error handling client: {e}")

        except KeyboardInterrupt:
            logger.info("Server interrupted by user")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if hasattr(self.transport, 'cleanup'):
                self.transport.cleanup()
            logger.info("MCP server stopped")

    def _run_stdio_server(self) -> None:
        """Run stdio server (single client)."""
        try:
            while True:
                message = self.transport.read_message()
                if message is None:
                    break
                self.handle_request(message)

        except KeyboardInterrupt:
            logger.info("Server interrupted by user")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            logger.info("MCP server stopped")


def main():
    """Main entry point for MCP server."""
    parser = argparse.ArgumentParser(description="MCP server for CTI tools")
    parser.add_argument("--transport", choices=["stdio", "tcp"], default="stdio",
                        help="Transport type (default: stdio)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="IP address to bind TCP server (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765,
                        help="Port to bind TCP server (default: 8765)")

    args = parser.parse_args()

    # Setup logging to stderr so it doesn't interfere with JSON-RPC on stdout
    setup_logging()

    # Redirect default logging to stderr for stdio transport
    if args.transport == "stdio":
        import sys
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.INFO)
            if hasattr(handler, 'stream') and handler.stream == sys.stdout:
                handler.setStream(sys.stderr)

    server = MCPServer(
        transport_type=args.transport,
        host=args.host,
        port=args.port
    )
    server.run()


if __name__ == "__main__":
    main()