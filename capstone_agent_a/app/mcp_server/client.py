import json
import subprocess
import sys
from typing import Any, Dict, List


class MCPClient:

    def __init__(self, server_command: List[str]):
        self.server_command = server_command
        self.process = None
        self.request_id = 1

    def start_server(self) -> None:
        self.process = subprocess.Popen(
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0
        )

    def stop_server(self) -> None:
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None

    def send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        if not self.process:
            raise RuntimeError("Server not started")

        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method
        }

        if params:
            request["params"] = params

        self.request_id += 1

        # Send request
        request_json = json.dumps(request) + "\n"
        self.process.stdin.write(request_json)
        self.process.stdin.flush()

        # Read response
        response_line = self.process.stdout.readline()
        if not response_line:
            raise RuntimeError("No response from server")

        return json.loads(response_line)

    def list_tools(self) -> List[Dict[str, Any]]:
        response = self.send_request("tools/list")
        if "result" in response:
            return response["result"]["tools"]
        else:
            raise RuntimeError(f"Error: {response.get('error')}")

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        response = self.send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })
        if "result" in response:
            return response["result"]["result"]
        else:
            raise RuntimeError(f"Error: {response.get('error')}")
