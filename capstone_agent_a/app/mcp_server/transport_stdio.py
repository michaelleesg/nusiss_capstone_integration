"""Stdio JSON-RPC transport for MCP server."""

import json
import logging
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class StdioTransport:
    """Stdio JSON-RPC transport."""

    def __init__(self):
        self.request_id = 0

    def read_message(self) -> Optional[Dict[str, Any]]:
        """Read a JSON-RPC message from stdin."""
        try:
            line = sys.stdin.readline()
            if not line:
                return None

            line = line.strip()
            if not line:
                return None

            message = json.loads(line)
            logger.debug(f"Received message: {message}")
            return message

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON received: {e}")
            return None
        except Exception as e:
            logger.error(f"Error reading message: {e}")
            return None

    def write_message(self, message: Dict[str, Any]) -> None:
        """Write a JSON-RPC message to stdout."""
        try:
            json_str = json.dumps(message, separators=(',', ':'))
            print(json_str, flush=True)
            logger.debug(f"Sent message: {message}")

        except Exception as e:
            logger.error(f"Error writing message: {e}")

    def send_response(self, request_id: Any, result: Any) -> None:
        """Send a successful response."""
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result
        }
        self.write_message(response)

    def send_error(self, request_id: Any, code: int, message: str, data: Any = None) -> None:
        """Send an error response."""
        error = {
            "code": code,
            "message": message
        }
        if data is not None:
            error["data"] = data

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error
        }
        self.write_message(response)

    def send_notification(self, method: str, params: Any = None) -> None:
        """Send a notification (no response expected)."""
        notification = {
            "jsonrpc": "2.0",
            "method": method
        }
        if params is not None:
            notification["params"] = params

        self.write_message(notification)