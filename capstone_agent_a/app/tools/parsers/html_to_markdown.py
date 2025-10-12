"""HTML to markdown converter using html2text library."""

import logging
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class HTMLToMarkdownInput(BaseModel):
    """Input for HTML to markdown converter."""

    html: str = Field(description="HTML content")
    url: str = Field(description="Source URL for link resolution")


class HTMLToMarkdownOutput(BaseModel):
    """Output for HTML to markdown converter."""

    markdown: str = Field(description="Converted markdown content")
    metadata: Dict[str, Optional[str]] = Field(description="Extracted metadata")


def extract_metadata(soup) -> Dict[str, Optional[str]]:
    """Extract metadata from HTML."""
    metadata = {
        "title": None,
        "author": None,
        "description": None,
        "published_date": None,
        "site_name": None
    }

    try:
        # Title from title tag
        title_tag = soup.find("title")
        if title_tag:
            metadata["title"] = title_tag.get_text().strip()

        # Meta tags
        meta_tags = soup.find_all("meta")
        for meta in meta_tags:
            name = meta.get("name", "").lower()
            property_attr = meta.get("property", "").lower()
            content = meta.get("content", "")

            if not content:
                continue

            # Author
            if name in ["author", "article:author"] or property_attr == "article:author":
                metadata["author"] = content

            # Description
            elif name == "description" or property_attr == "og:description":
                metadata["description"] = content

            # Published date
            elif (name in ["published_time", "article:published_time"] or
                  property_attr in ["article:published_time", "article:published"]):
                metadata["published_date"] = content

            # Site name
            elif property_attr == "og:site_name":
                metadata["site_name"] = content

        # Try to extract from JSON-LD structured data
        json_ld_scripts = soup.find_all("script", type="application/ld+json")
        for script in json_ld_scripts:
            try:
                import json
                data = json.loads(script.string)
                if isinstance(data, dict):
                    if "headline" in data and not metadata["title"]:
                        metadata["title"] = data["headline"]
                    if "author" in data and not metadata["author"]:
                        author = data["author"]
                        if isinstance(author, dict) and "name" in author:
                            metadata["author"] = author["name"]
                        elif isinstance(author, str):
                            metadata["author"] = author
                    if "datePublished" in data and not metadata["published_date"]:
                        metadata["published_date"] = data["datePublished"]
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"Error extracting metadata: {e}")

    return metadata


def configure_html2text_converter(base_url: str):
    """Configure html2text converter with optimal settings for CTI content."""
    try:
        import html2text

        converter = html2text.HTML2Text(baseurl=base_url)

        # Core content preservation settings
        converter.ignore_links = False  # Keep links for IOC/reference extraction
        converter.ignore_images = True  # Skip images to focus on text content
        converter.ignore_emphasis = False  # Keep bold/italic formatting
        converter.body_width = 0  # No line wrapping to preserve structure

        # Clean output settings
        converter.unicode_snob = True  # Use unicode instead of ASCII approximations
        converter.escape_snob = True  # Don't escape special markdown characters unnecessarily
        converter.mark_code = True  # Preserve code blocks

        # Content filtering settings
        converter.ignore_anchors = True  # Remove anchor links (#section)
        converter.skip_internal_links = False  # Keep internal links for analysis
        converter.single_line_break = False  # Use proper paragraph breaks

        # Advanced content handling
        converter.wrap_links = False  # Don't wrap long URLs
        converter.wrap_list_items = False  # Keep list items on single lines when possible
        converter.default_image_alt = ""  # Clean alt text handling

        return converter

    except ImportError:
        logger.warning("html2text library not available, falling back to BeautifulSoup")
        return None


def clean_html_content(soup):
    """Remove non-essential HTML elements before conversion."""
    # Remove navigation, ads, and non-content elements
    unwanted_selectors = [
        "nav", "header", "footer", "aside",  # Navigation and structural elements
        ".nav", ".navigation", ".navbar",   # Navigation classes
        ".sidebar", ".side-bar", ".aside",  # Sidebar content
        ".advertisement", ".ads", ".ad",    # Advertisements
        ".social", ".social-media", ".share", # Social media widgets
        ".related", ".recommended",         # Related content sections
        ".comments", ".comment-section",    # Comment sections
        ".cookie", ".gdpr", ".consent",     # Cookie/consent notices
        ".popup", ".modal", ".overlay",     # Popup overlays
        ".breadcrumb", ".breadcrumbs",      # Breadcrumb navigation
        ".pagination", ".pager",            # Pagination elements
        ".tag", ".tags", ".categories",     # Tag/category widgets
        "[role='complementary']",           # Complementary content
        "[role='banner']",                  # Banner content
        "[role='navigation']",              # Navigation roles
        "[class*='widget']",                # Widget elements
        "[id*='sidebar']",                  # Sidebar IDs
        "[id*='footer']",                   # Footer IDs
        "[id*='header']",                   # Header IDs
    ]

    for selector in unwanted_selectors:
        try:
            elements = soup.select(selector)
            for element in elements:
                element.decompose()
        except Exception:
            continue

    # Remove script, style, and other non-content elements
    for element in soup(["script", "style", "noscript", "iframe", "embed", "object"]):
        element.decompose()

    # Remove HTML comments
    from bs4 import Comment
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        comment.extract()

    return soup


def post_process_markdown(markdown_content: str) -> str:
    """Post-process markdown content for better CTI analysis."""
    import re

    # Clean up excessive whitespace while preserving structure
    markdown_content = re.sub(r'\n{4,}', '\n\n\n', markdown_content)  # Max 3 newlines
    markdown_content = re.sub(r'[ \t]+', ' ', markdown_content)  # Normalize spaces
    markdown_content = re.sub(r'^ +', '', markdown_content, flags=re.MULTILINE)  # Remove leading spaces

    # Clean up malformed headers
    markdown_content = re.sub(r'^(#{1,6})\s*$', '', markdown_content, flags=re.MULTILINE)  # Remove empty headers

    # Normalize list formatting
    markdown_content = re.sub(r'\n\s*[\*\-\+]\s*\n', '\n', markdown_content)  # Remove empty list items

    # Clean up link formatting - remove tracking parameters
    def clean_link(match):
        link_text = match.group(1)
        url = match.group(2)

        # Remove common tracking parameters
        tracking_params = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
                          'fbclid', 'gclid', 'ref', 'source', 'campaign']

        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        try:
            parsed = urlparse(url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                # Remove tracking parameters
                clean_params = {k: v for k, v in query_params.items()
                               if not any(track in k.lower() for track in tracking_params)}
                clean_query = urlencode(clean_params, doseq=True)
                clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                      parsed.params, clean_query, parsed.fragment))
                return f'[{link_text}]({clean_url})'
        except Exception:
            pass

        return f'[{link_text}]({url})'

    markdown_content = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', clean_link, markdown_content)

    # Ensure proper header hierarchy (no jumps from h1 to h3)
    lines = markdown_content.split('\n')
    processed_lines = []
    current_level = 0

    for line in lines:
        if line.strip().startswith('#'):
            header_match = re.match(r'^(#{1,6})\s*(.*)', line.strip())
            if header_match:
                new_level = len(header_match.group(1))
                header_text = header_match.group(2).strip()

                # Ensure we don't skip more than one header level
                if new_level > current_level + 1:
                    new_level = current_level + 1

                current_level = new_level
                processed_lines.append('#' * new_level + ' ' + header_text)
            else:
                processed_lines.append(line)
        else:
            processed_lines.append(line)

    return '\n'.join(processed_lines).strip()


def html_to_markdown(input_data: HTMLToMarkdownInput) -> HTMLToMarkdownOutput:
    """Convert HTML to markdown with metadata extraction using html2text."""
    try:
        from bs4 import BeautifulSoup

        # Parse HTML with BeautifulSoup for cleaning and metadata extraction
        soup = BeautifulSoup(input_data.html, "lxml")

        # Extract metadata first
        metadata = extract_metadata(soup)

        # Try to find main content area
        main_content_html = None

        # Look for common content selectors (prioritized for CTI content)
        content_selectors = [
            "article",                    # Semantic article content
            "[role='main']",             # ARIA main role
            ".post-content",             # Blog post content
            ".entry-content",            # Entry/article content
            ".article-body",             # Article body
            ".story-body",               # News story body
            ".content-body",             # Content body
            ".main-content",             # Main content area
            "#main-content",             # Main content ID
            ".content",                  # Generic content
            "#content",                  # Generic content ID
            ".text-content",             # Text content area
            "[itemprop='articleBody']",  # Schema.org article body
        ]

        # Find the best content area by evaluating multiple candidates
        candidate_contents = []

        for selector in content_selectors:
            try:
                element = soup.select_one(selector)
                if element and element.get_text(strip=True):
                    text_content = element.get_text(strip=True)
                    # Score content based on length and meaningful content indicators
                    score = len(text_content)

                    # Boost score for content that mentions the title keywords
                    title_keywords = title.lower().split() if title else []
                    for keyword in title_keywords:
                        if len(keyword) > 3:  # Skip short words
                            score += text_content.lower().count(keyword) * 100

                    candidate_contents.append({
                        'selector': selector,
                        'element': element,
                        'text_length': len(text_content),
                        'score': score,
                        'html': str(element)
                    })
                    logger.debug(f"Content candidate: {selector}, length: {len(text_content)}, score: {score}")
            except Exception:
                continue

        # Select the highest scoring content
        if candidate_contents:
            best_candidate = max(candidate_contents, key=lambda x: x['score'])
            main_content_html = best_candidate['html']
            logger.info(f"Selected content using selector: {best_candidate['selector']} (length: {best_candidate['text_length']}, score: {best_candidate['score']})")
        else:
            main_content_html = None

        # If no main content found, try body or the whole document
        if not main_content_html:
            body = soup.find("body")
            if body:
                # Clean the body before using it
                cleaned_soup = clean_html_content(BeautifulSoup(str(body), "lxml"))
                main_content_html = str(cleaned_soup)
            else:
                # Last resort: use the entire document
                cleaned_soup = clean_html_content(soup)
                main_content_html = str(cleaned_soup)

        # Try to use html2text for conversion
        converter = configure_html2text_converter(input_data.url)

        if converter:
            try:
                # Convert using html2text
                markdown = converter.handle(main_content_html)

                # Post-process the markdown
                markdown = post_process_markdown(markdown)

                logger.info(f"Converted HTML to markdown using html2text: {len(markdown)} chars")

            except Exception as e:
                logger.warning(f"html2text conversion failed: {e}, falling back to BeautifulSoup")
                # Fallback to BeautifulSoup extraction
                fallback_soup = BeautifulSoup(main_content_html, "lxml")
                cleaned_soup = clean_html_content(fallback_soup)
                markdown = cleaned_soup.get_text(separator="\n\n", strip=True)
        else:
            # Use BeautifulSoup fallback
            logger.info("Using BeautifulSoup fallback for HTML conversion")
            fallback_soup = BeautifulSoup(main_content_html, "lxml")
            cleaned_soup = clean_html_content(fallback_soup)
            markdown = cleaned_soup.get_text(separator="\n\n", strip=True)

        # Final cleanup and validation
        if not markdown.strip():
            # Emergency fallback: extract any text from the original HTML
            emergency_soup = BeautifulSoup(input_data.html, "html.parser")
            markdown = emergency_soup.get_text(separator="\n", strip=True)
            logger.warning("Used emergency text extraction fallback")

        logger.info(
            f"HTML to markdown conversion complete: {len(markdown)} chars, "
            f"title: {metadata.get('title', 'None')}"
        )

        return HTMLToMarkdownOutput(
            markdown=markdown,
            metadata=metadata
        )

    except Exception as e:
        logger.error(f"Error in HTML to markdown conversion: {e}")
        # Final fallback: try to extract basic text
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(input_data.html, "html.parser")
            fallback_text = soup.get_text(separator="\n", strip=True)
            return HTMLToMarkdownOutput(
                markdown=fallback_text,
                metadata={"title": None, "author": None, "description": None,
                         "published_date": None, "site_name": None}
            )
        except Exception:
            return HTMLToMarkdownOutput(
                markdown="Error: Could not parse HTML content",
                metadata={"title": None, "author": None, "description": None,
                         "published_date": None, "site_name": None}
            )


# Tool registration for MCP
TOOL_NAME = "html.to_markdown"
TOOL_DESCRIPTION = "Convert HTML to markdown with metadata extraction"
INPUT_SCHEMA = HTMLToMarkdownInput.model_json_schema()
OUTPUT_SCHEMA = HTMLToMarkdownOutput.model_json_schema()