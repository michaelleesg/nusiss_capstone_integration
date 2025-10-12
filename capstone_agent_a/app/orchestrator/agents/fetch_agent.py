"""Fetch agent for URL content retrieval."""

import base64

from .base_agent import BaseAgent
from ...state import GraphState
from ...memory import get_memory_system
from ...tool_proxy import call_tool


class FetchAgent(BaseAgent):
    """Agent responsible for fetching URL content and memory checking."""

    def __init__(self):
        super().__init__("fetch")

    def get_system_prompt(self) -> str:
        """Get system prompt for fetch agent."""
        return """You are a content fetch agent for retrieving feeds for Cyber Threat Intelligence analysis.

Your responsibilities:
1. Fetch URL content using HTTP tools
2. Check memory system for previously processed content
3. Handle short-circuiting for duplicate content
4. Store content records for tracking

Always prioritize efficiency and avoid redundant processing."""

    def process(self, state: GraphState) -> GraphState:
        """Fetch URL content and check for duplicates."""
        try:
            self.log_processing("Starting fetch", {"url": state.url})

            # Check memory first
            memory = get_memory_system()

            # Fetch content via tool proxy (MCP or direct)
            fetch_kwargs = {"url": state.url, "verify_ssl": state.verify_ssl}
            if state.auth_username and state.auth_password:
                fetch_kwargs["username"] = state.auth_username
                fetch_kwargs["password"] = state.auth_password
            fetch_result = call_tool("http_fetch", **fetch_kwargs)

            # Check if we've seen this content before
            existing = memory.check_content_exists(state.url, fetch_result["sha256"])

            if existing and existing.get("short_circuit"):
                self.log_processing("Short-circuiting", {"reason": "content already processed"})
                # Load existing artifact
                artifact_data = memory.load_artifact(existing["artifact_path"])
                if artifact_data:
                    # Return completed state
                    state.extracted = artifact_data
                    return state

            # Store content record - handle constraint errors gracefully
            # Skip memory storage for RSS feeds since they are URL containers, not final content
            # Quick RSS detection based on content patterns
            should_skip_storage = False
            if fetch_result.get("content_b64"):
                try:
                    content_bytes = base64.b64decode(fetch_result["content_b64"])
                    content_text = content_bytes.decode('utf-8', errors='ignore')[:1000]  # Check first 1KB
                    # Simple RSS detection
                    if ('<rss' in content_text.lower() and 'version=' in content_text.lower()) or \
                       ('<feed' in content_text.lower() and 'xmlns=' in content_text.lower()):
                        should_skip_storage = True
                        self.logger.info(f"Detected RSS/Atom feed - skipping memory storage for container URL: {state.url}")
                except Exception:
                    pass

            if not should_skip_storage:
                try:
                    memory.store_content_record(
                        url=state.url,
                        content_hash=fetch_result["sha256"],
                        mime=fetch_result["mime"]
                    )
                except Exception as db_error:
                    # Database storage failed, but fetch succeeded - continue with processing
                    if "UNIQUE constraint failed" in str(db_error):
                        self.logger.info(f"Content already exists in database (SHA256: {fetch_result['sha256'][:16]}...), continuing with processing")
                    else:
                        self.logger.warning(f"Database storage failed: {db_error}, continuing with processing")

            # Always set fetched state with actual content
            state.fetched = {
                "status": fetch_result["status"],
                "headers": fetch_result["headers"],
                "mime": fetch_result["mime"],
                "content_b64": fetch_result["content_b64"],
                "sha256": fetch_result["sha256"]
            }

            self.log_processing("Fetch complete", {
                "mime": fetch_result["mime"],
                "size": len(fetch_result["content_b64"]),
                "sha256": fetch_result["sha256"][:16] + "..."
            })

            return state

        except Exception as e:
            self.logger.error(f"Error in fetch processing: {e}")
            # Return error state only for actual fetch failures
            state.fetched = {
                "status": 500,
                "headers": {},
                "mime": "text/plain",
                "content_b64": base64.b64encode(f"Fetch error: {str(e)}".encode()).decode(),
                "sha256": ""
            }
            return state