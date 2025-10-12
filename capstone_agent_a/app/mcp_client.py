"""MCP client wrapper for agents to access tools."""

import json
import logging
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class MCPClient:
    """Client for communicating with MCP server using stdio or TCP."""

    def __init__(self,
                 server_command: Optional[List[str]] = None,
                 use_tcp: bool = False,
                 host: str = "127.0.0.1",
                 port: int = 8765,
                 start_server: bool = True):
        """Initialize MCP client.

        Args:
            server_command: Command to start MCP server. Uses existing server module.
            use_tcp: Whether to use TCP transport instead of stdio
            host: IP address for TCP connection
            port: Port for TCP connection
            start_server: Whether to start server process or connect to existing one
        """
        self.start_server = start_server
        base_command = [sys.executable, "-m", "app.mcp_server.server"]

        if use_tcp:
            self.server_command = server_command or (base_command + [
                "--transport", "tcp", "--host", host, "--port", str(port)
            ])
            self.use_tcp = True
            self.host = host
            self.port = port
            self.socket = None
        else:
            self.server_command = server_command or base_command
            self.use_tcp = False

        self.process = None
        self.request_id = 1
        self._tools_cache = None
        self._lock = threading.Lock()

    def __enter__(self):
        """Start MCP server process."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop MCP server process."""
        self.stop()

    def start(self):
        """Start the MCP server process and connection."""
        try:
            if self.start_server:
                # Start MCP server process
                self.process = subprocess.Popen(
                    self.server_command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=0
                )
                logger.info("MCP server process started")

                if self.use_tcp:
                    # Give server time to start
                    time.sleep(1.0)

            if self.use_tcp:
                # Connect to TCP server (either started above or external)
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                if self.start_server:
                    logger.info(f"MCP client connected to started TCP server at {self.host}:{self.port}")
                else:
                    logger.info(f"MCP client connected to existing TCP server at {self.host}:{self.port}")
            else:
                if not self.start_server:
                    raise ValueError("Cannot use stdio transport with external server (start_server=False)")
                logger.info("MCP server started (stdio)")

        except Exception as e:
            logger.error(f"Failed to start/connect to MCP server: {e}")
            self.cleanup()
            raise

    def stop(self):
        """Stop the MCP server process and connection."""
        self.cleanup()

    def cleanup(self):
        """Clean up resources."""
        # Close TCP socket
        if hasattr(self, 'socket') and self.socket:
            try:
                self.socket.close()
                logger.info("TCP connection closed")
            except Exception as e:
                logger.error(f"Error closing TCP socket: {e}")
            finally:
                self.socket = None

        # Stop server process only if we started it
        if self.process and self.start_server:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                logger.info("MCP server stopped")
            except subprocess.TimeoutExpired:
                self.process.kill()
                logger.warning("MCP server forcefully killed")
            except Exception as e:
                logger.error(f"Error stopping MCP server: {e}")
            finally:
                self.process = None

    def _get_request_id(self) -> int:
        """Get next request ID."""
        with self._lock:
            current_id = self.request_id
            self.request_id += 1
            return current_id

    def _send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send request to MCP server and get response."""
        # Check if we have a valid connection
        if self.use_tcp:
            if not self.socket:
                raise RuntimeError("TCP connection not established")
        else:
            if not self.process:
                raise RuntimeError("MCP server not started")

        try:
            request = {
                "jsonrpc": "2.0",
                "id": self._get_request_id(),
                "method": method
            }

            if params:
                request["params"] = params

            if self.use_tcp:
                return self._send_tcp_request(request)
            else:
                return self._send_stdio_request(request)

        except Exception as e:
            logger.error(f"MCP request failed: {e}")
            raise

    def _send_stdio_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send request via stdio."""
        request_json = json.dumps(request) + "\n"
        self.process.stdin.write(request_json)
        self.process.stdin.flush()

        response_line = self.process.stdout.readline()
        if not response_line:
            raise RuntimeError("No response from MCP server")

        return json.loads(response_line.strip())

    def _send_tcp_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send request via TCP."""
        if not self.socket:
            raise RuntimeError("TCP socket not connected")

        # Send request with length prefix
        request_json = json.dumps(request)
        request_bytes = request_json.encode('utf-8')
        length_bytes = len(request_bytes).to_bytes(4, byteorder='big')
        self.socket.send(length_bytes + request_bytes)

        # Read response length
        length_data = self.socket.recv(4)
        if not length_data:
            raise RuntimeError("No response from TCP server")

        response_length = int.from_bytes(length_data, byteorder='big')

        # Read response data
        response_data = b""
        while len(response_data) < response_length:
            chunk = self.socket.recv(response_length - len(response_data))
            if not chunk:
                raise RuntimeError("Connection closed during response")
            response_data += chunk

        return json.loads(response_data.decode('utf-8'))

    def list_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools from MCP server."""
        if self._tools_cache is not None:
            return self._tools_cache

        response = self._send_request("tools/list")

        if "result" in response:
            tools = response["result"]["tools"]
            self._tools_cache = tools
            logger.info(f"Retrieved {len(tools)} tools from MCP server")
            return tools
        else:
            error_msg = f"Failed to list tools: {response.get('error')}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the MCP server."""
        start_time = time.time()

        response = self._send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })

        duration = time.time() - start_time

        if "result" in response:
            result = response["result"]["result"]
            logger.debug(f"Tool {name} completed in {duration:.3f}s")
            return result
        else:
            error_msg = f"Tool {name} failed: {response.get('error')}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)


# Global MCP client instance - lazy initialized
_mcp_client = None
_client_lock = threading.Lock()


def get_mcp_client() -> MCPClient:
    """Get global MCP client instance."""
    global _mcp_client

    with _client_lock:
        if _mcp_client is None:
            _mcp_client = MCPClient()
            _mcp_client.start()
        return _mcp_client


def call_mcp_tool(name: str, arguments: Dict[str, Any]) -> Any:
    """Convenience function to call MCP tool."""
    client = get_mcp_client()
    return client.call_tool(name, arguments)


def list_mcp_tools() -> List[Dict[str, Any]]:
    """Convenience function to list MCP tools."""
    client = get_mcp_client()
    return client.list_tools()


# Cleanup function for graceful shutdown
def cleanup_mcp_client():
    """Clean up global MCP client."""
    global _mcp_client

    with _client_lock:
        if _mcp_client is not None:
            _mcp_client.stop()
            _mcp_client = None