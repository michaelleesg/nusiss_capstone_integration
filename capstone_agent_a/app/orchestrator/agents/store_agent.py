"""Storage and emission agent."""

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.store_emit import store_emit, StoreInput


class StoreAgent(BaseAgent):
    """Agent responsible for storing final artifacts."""

    def __init__(self):
        super().__init__("store")

    def get_system_prompt(self) -> str:
        return """You are a Cyber Threat Intelligence (CTI) artifact storage agent.

Your responsibilities:

STORAGE OPERATIONS:
- Write JSON artifacts to local filesystem
- Optionally upload to S3 cloud storage
- Generate unique filenames based on content hash
- Ensure proper JSON formatting and encoding

FILE MANAGEMENT:
- Use SHA-256 hash for filenames
- Store in configured output directory
- Handle file permissions and access
- Verify successful write operations

METADATA TRACKING:
- Update memory system with artifact paths
- Enable future short-circuiting
- Record storage locations and timestamps
- Maintain audit trail

ERROR HANDLING:
- Graceful handling of storage failures
- Fallback storage options
- Proper error reporting
- No data loss on failures

Always ensure artifacts are safely persisted and accessible for future use."""

    def process(self, state: GraphState) -> GraphState:
        """Store final CTI artifact."""
        try:
            store_input = StoreInput(json=state.extracted, path=None, s3=None)
            store_result = store_emit(store_input)

            self.log_processing("Artifact storage complete", {
                "written": store_result.written,
                "locator": store_result.locator
            })

            if store_result.written:
                # Extract file path from locator for user-friendly message
                if store_result.locator.startswith("file://"):
                    file_path = store_result.locator[7:]  # Remove "file://" prefix
                    print(f"📄 Output file ready: {file_path}")
            else:
                self.logger.warning("Storage operation failed")

            return state

        except Exception as e:
            self.logger.error(f"Error in artifact storage: {e}")
            return state