"""TCP network transport for MCP server."""

import json
import logging
import socket
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class TcpTransport:
    """TCP network transport for MCP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        """Initialize TCP transport.

        Args:
            host: IP address to bind to
            port: Port to bind to
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self._lock = threading.Lock()

    def start_server(self) -> None:
        """Start TCP server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)  # Allow multiple queued connections

            logger.info(f"MCP server listening on {self.host}:{self.port}")

        except Exception as e:
            logger.error(f"Error starting TCP server: {e}")
            self.cleanup()
            raise

    def accept_client(self) -> bool:
        """Accept next client connection. Returns False if server should stop."""
        try:
            if not self.server_socket:
                return False

            logger.info("Waiting for client connection...")
            self.client_socket, self.client_address = self.server_socket.accept()
            logger.info(f"Client connected from {self.client_address}")
            return True

        except Exception as e:
            logger.error(f"Error accepting client: {e}")
            return False

    def read_message(self) -> Optional[Dict[str, Any]]:
        """Read JSON-RPC message from client."""
        if not self.client_socket:
            return None

        try:
            # Read message length (4 bytes)
            length_data = self.client_socket.recv(4)
            if not length_data:
                return None

            message_length = int.from_bytes(length_data, byteorder='big')

            # Read message data
            message_data = b""
            while len(message_data) < message_length:
                chunk = self.client_socket.recv(message_length - len(message_data))
                if not chunk:
                    return None
                message_data += chunk

            # Parse JSON
            message_str = message_data.decode('utf-8')
            message = json.loads(message_str)
            logger.debug(f"Received: {message}")
            return message

        except (ConnectionError, socket.error) as e:
            logger.info(f"Client disconnected: {e}")
            self._close_client()
            return None
        except Exception as e:
            logger.error(f"Error reading message: {e}")
            self._close_client()
            return None

    def _close_client(self) -> None:
        """Close current client connection."""
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
            self.client_address = None

    def send_response(self, request_id: Any, result: Dict[str, Any]) -> None:
        """Send JSON-RPC response."""
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result
        }
        self._send_json(response)

    def send_error(self, request_id: Any, code: int, message: str) -> None:
        """Send JSON-RPC error response."""
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message
            }
        }
        self._send_json(response)

    def _send_json(self, data: Dict[str, Any]) -> None:
        """Send JSON data over TCP."""
        if not self.client_socket:
            return

        try:
            with self._lock:
                message_str = json.dumps(data)
                message_bytes = message_str.encode('utf-8')

                # Send length prefix (4 bytes) then message
                length_bytes = len(message_bytes).to_bytes(4, byteorder='big')
                self.client_socket.send(length_bytes + message_bytes)

                logger.debug(f"Sent: {data}")

        except Exception as e:
            logger.error(f"Error sending message: {e}")

    def cleanup(self) -> None:
        """Clean up TCP resources."""
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        logger.info("TCP transport cleaned up")