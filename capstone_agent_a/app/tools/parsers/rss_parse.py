"""RSS/Atom feed parser."""

import logging
from typing import Any, Dict, List, Optional

import feedparser
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class RSSParseInput(BaseModel):
    """Input for RSS parser."""

    xml: str = Field(description="RSS/Atom XML content")


class RSSItem(BaseModel):
    """RSS item structure."""

    title: str = Field(description="Item title")
    link: str = Field(description="Item link")
    summary: Optional[str] = Field(description="Item summary/description")
    published: Optional[str] = Field(description="Publication date")
    content: Optional[str] = Field(description="Full content if available")


class RSSParseOutput(BaseModel):
    """Output for RSS parser."""

    items: List[RSSItem] = Field(description="Parsed RSS items")
    feed: Dict[str, Any] = Field(description="Feed metadata")


def clean_html_content(content: str) -> str:
    """Clean HTML from content while preserving text."""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(content, "html.parser")
        return soup.get_text(strip=True, separator="\n")
    except Exception:
        # Fallback: simple tag removal
        import re
        clean = re.sub(r"<[^>]+>", "", content)
        return clean.strip()


def parse_rss_item(entry: Any) -> Optional[RSSItem]:
    """Parse a single RSS/Atom entry."""
    try:
        # Extract title
        title = getattr(entry, "title", "Untitled")
        if hasattr(entry, "title_detail") and entry.title_detail:
            if entry.title_detail.get("type") == "text/html":
                title = clean_html_content(title)

        # Extract link
        link = getattr(entry, "link", "")

        # Extract summary/description
        summary = None
        if hasattr(entry, "summary"):
            summary = clean_html_content(entry.summary)
        elif hasattr(entry, "description"):
            summary = clean_html_content(entry.description)

        # Extract published date
        published = None
        if hasattr(entry, "published"):
            published = entry.published
        elif hasattr(entry, "updated"):
            published = entry.updated

        # Extract full content
        content = None
        if hasattr(entry, "content") and entry.content:
            # Multiple content entries possible
            content_parts = []
            for content_item in entry.content:
                if hasattr(content_item, "value"):
                    content_parts.append(clean_html_content(content_item.value))
            content = "\n\n".join(content_parts) if content_parts else None

        # If no content but have summary, use summary as content
        if not content and summary:
            content = summary

        return RSSItem(
            title=title,
            link=link,
            summary=summary,
            published=published,
            content=content
        )

    except Exception as e:
        logger.warning(f"Error parsing RSS item: {e}")
        return None


def parse_feed_metadata(feed: Any) -> Dict[str, Any]:
    """Parse feed-level metadata."""
    try:
        metadata = {
            "title": getattr(feed, "title", ""),
            "description": getattr(feed, "description", ""),
            "link": getattr(feed, "link", ""),
            "language": getattr(feed, "language", ""),
            "updated": getattr(feed, "updated", ""),
            "generator": getattr(feed, "generator", "")
        }

        # Clean HTML from description
        if metadata["description"]:
            metadata["description"] = clean_html_content(metadata["description"])

        # Add feed type if available
        if hasattr(feed, "version"):
            metadata["version"] = feed.version

        # Add publisher info
        if hasattr(feed, "publisher"):
            metadata["publisher"] = feed.publisher
        elif hasattr(feed, "managingEditor"):
            metadata["publisher"] = feed.managingEditor

        return metadata

    except Exception as e:
        logger.warning(f"Error parsing feed metadata: {e}")
        return {}


def rss_parse(input_data: RSSParseInput) -> RSSParseOutput:
    """Parse RSS/Atom feed."""
    try:
        # Parse with feedparser
        parsed = feedparser.parse(input_data.xml)

        if parsed.bozo and parsed.bozo_exception:
            logger.warning(f"Feed parsing warning: {parsed.bozo_exception}")

        # Parse feed metadata
        feed_metadata = parse_feed_metadata(parsed.feed)

        # Parse entries
        items = []
        for entry in parsed.entries:
            parsed_item = parse_rss_item(entry)
            if parsed_item:
                items.append(parsed_item)

        logger.info(
            f"Parsed RSS feed: {len(items)} items, "
            f"title: {feed_metadata.get('title', 'Unknown')}"
        )

        return RSSParseOutput(
            items=items,
            feed=feed_metadata
        )

    except Exception as e:
        logger.error(f"Error parsing RSS feed: {e}")
        return RSSParseOutput(
            items=[],
            feed={}
        )


# Tool registration for MCP
TOOL_NAME = "rss.parse"
TOOL_DESCRIPTION = "Parse RSS/Atom feed and extract items"
INPUT_SCHEMA = RSSParseInput.model_json_schema()
OUTPUT_SCHEMA = RSSParseOutput.model_json_schema()