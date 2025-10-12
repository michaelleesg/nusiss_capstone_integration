"""Truly agentic workflow that dynamically discovers and uses MCP tools."""

import logging
from typing import Any, Dict, List, Optional

from langgraph.graph import StateGraph

from .state import GraphState
from .orchestrator.agents.agentic_orchestrator import AgenticOrchestrator

logger = logging.getLogger(__name__)

# Global orchestrator
_orchestrator = None


def get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgenticOrchestrator()
    return _orchestrator


def agentic_processing_node(state: GraphState) -> GraphState:
    """Agentic processing that dynamically uses available MCP tools."""
    orchestrator = get_orchestrator()

    # The orchestrator handles the entire processing pipeline autonomously
    return orchestrator.process(state)








def create_cti_graph() -> StateGraph:
    """Create the truly agentic CTI processing workflow graph."""
    workflow = StateGraph(GraphState)

    # Single agentic processing node that handles everything
    workflow.add_node("agentic_processing", agentic_processing_node)

    # Start and end with agentic processing
    workflow.set_entry_point("agentic_processing")
    workflow.set_finish_point("agentic_processing")

    return workflow


def compile_graph() -> Any:
    """Compile the CTI workflow graph."""
    workflow = create_cti_graph()
    return workflow.compile()


def process_url(url: str, auth_username: Optional[str] = None, auth_password: Optional[str] = None, verify_ssl: bool = True, bypass_memory: bool = False) -> Dict[str, Any]:
    """Process a single URL through the CTI pipeline.

    Args:
        url: URL to process
        auth_username: Optional HTTP basic auth username
        auth_password: Optional HTTP basic auth password
        verify_ssl: Whether to verify SSL certificates (default: True)
        bypass_memory: Skip memory/deduplication check and reprocess URL (default: False)

    Returns:
        For non-RSS URLs: Single result dict
        For RSS URLs: Dict with 'is_rss_feed': True and 'results': List[Dict]
    """
    try:
        logger.info(f"Processing URL: {url}")

        # Early memory check for cronjob optimization (skip already processed URLs)
        # Skip this check if bypass_memory is True
        if not bypass_memory:
            from .memory import get_memory_system
            memory = get_memory_system()

            # Check if URL was already processed (skip memory check for RSS feeds)
            # RSS feeds should be processed each time to find new items
            existing = memory.check_url_processed(url)
            if existing:
                # Do a quick check to see if this might be an RSS feed
                # If so, allow reprocessing to find new items
                try:
                    import requests
                    # Quick HEAD request to check content type
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    content_type = response.headers.get('content-type', '').lower()

                    # Skip memory check for RSS/XML feeds
                    if any(feed_type in content_type for feed_type in ['rss', 'xml', 'atom', 'application/rss+xml', 'application/atom+xml']):
                        logger.info(f"Detected potential RSS feed, allowing reprocessing: {url}")
                    else:
                        logger.info(f"URL already processed, skipping: {url} (processed at: {existing['fetched_at']})")
                        return {
                            "url": url,
                            "success": True,
                            "skipped": True,
                            "reason": "already_processed",
                            "processed_at": existing["fetched_at"]
                        }
                except Exception:
                    # If we can't check content type, err on the side of caution and skip
                    logger.info(f"URL already processed, skipping: {url} (processed at: {existing['fetched_at']})")
                    return {
                        "url": url,
                        "success": True,
                        "skipped": True,
                        "reason": "already_processed",
                        "processed_at": existing["fetched_at"]
                    }
        else:
            logger.info(f"Memory check bypassed, reprocessing URL: {url}")

        # Create initial state
        initial_state = GraphState(url=url, auth_username=auth_username, auth_password=auth_password, verify_ssl=verify_ssl)

        # Compile and run graph
        app = compile_graph()
        result = app.invoke(initial_state)

        logger.info(f"Processing complete for {url}")

        # Debug: Check what we got back
        logger.info(f"DEBUG: result type = {type(result)}")
        logger.info(f"DEBUG: result.keys() = {result.keys() if isinstance(result, dict) else 'Not a dict'}")
        logger.info(f"DEBUG: detected_type = {result.get('detected_type') if isinstance(result, dict) else 'N/A'}")
        logger.info(f"DEBUG: has rss_results = {bool(result.get('rss_results')) if isinstance(result, dict) else 'N/A'}")
        logger.info(f"DEBUG: rss_results length = {len(result.get('rss_results', [])) if isinstance(result, dict) else 'N/A'}")

        # Check if this was an RSS feed with multiple items processed
        if (result.get("detected_type") == "RSS" and
            result.get("rss_results") and
            len(result.get("rss_results", [])) > 0):

            logger.info(f"DEBUG: RSS feed path taken - returning {len(result['rss_results'])} results to CLI")
            logger.info(f"RSS feed processed with {len(result['rss_results'])} items")

            # Return list of results for RSS feeds
            return {
                "url": url,
                "success": True,
                "is_rss_feed": True,
                "results": result["rss_results"],
                "feed_metadata": {
                    "title": result.get("extracted", {}).get("rss_feed_title", ""),
                    "description": result.get("extracted", {}).get("rss_feed_description", ""),
                    "item_count": len(result["rss_results"]),
                    "successful_count": result.get("extracted", {}).get("rss_successful_count", 0),
                    "failed_count": result.get("extracted", {}).get("rss_failed_count", 0)
                },
                "sha256": result.get("fetched", {}).get("sha256", "") if result.get("fetched") else "",
                "content_type": result.get("detected_type"),
                "token_usage": result.get("token_usage", {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "processing_time": 0.0,
                    "agents": {}
                })
            }

        # Return single result for non-RSS URLs
        return {
            "url": url,
            "success": True,
            "is_rss_feed": False,
            "data": result.get("extracted"),
            "evidence": result.get("evidence", []),
            "sha256": result.get("fetched", {}).get("sha256", "") if result.get("fetched") else "",
            "content_type": result.get("detected_type"),
            "token_usage": result.get("token_usage", {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "processing_time": 0.0,
                "agents": {}
            })
        }

    except Exception as e:
        logger.error(f"Error processing URL {url}: {e}")
        return {
            "url": url,
            "success": False,
            "is_rss_feed": False,
            "error": str(e),
            "data": None,
            "token_usage": {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "processing_time": 0.0,
                "agents": {}
            }
        }