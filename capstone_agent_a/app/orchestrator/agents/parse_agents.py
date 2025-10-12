"""Content parsing agents for different formats."""

import base64
import json

from .base_agent import BaseAgent
from ...state import GraphState
from ...tools.parsers.misp_parse import misp_parse_event, MISPParseInput
from ...tools.parsers.stix_parse import stix_parse_bundle, STIXParseInput
from ...tools.parsers.rss_parse import rss_parse, RSSParseInput
from ...tools.parsers.html_to_markdown import html_to_markdown, HTMLToMarkdownInput
from ...tools.parsers.pdf_to_text import pdf_to_text, PDFToTextInput
from ...tools.parsers.json_normalize import json_normalize, JSONNormalizeInput


class MISPParseAgent(BaseAgent):
    """Agent for parsing MISP content."""

    def __init__(self):
        super().__init__("parse_misp")

    def get_system_prompt(self) -> str:
        return """You are a MISP event parser for CTI analysis.

Parse MISP event JSON and extract:
- Event metadata (title, description, tags)
- Attributes with categories and values
- Object relationships

Handle various MISP JSON structures gracefully."""

    def process(self, state: GraphState) -> GraphState:
        try:
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            content_text = content_bytes.decode('utf-8', errors='ignore')

            # Parse as JSON
            misp_data = json.loads(content_text)
            parse_input = MISPParseInput(json=misp_data)
            parse_result = misp_parse_event(parse_input)

            state.parsed = {
                "type": "MISP",
                "title": parse_result.title,
                "attributes": parse_result.attributes,
                "tags": parse_result.tags
            }

            # Extract text for further processing
            text_parts = [parse_result.title or ""]
            text_parts.extend([attr.get("value", "") for attr in parse_result.attributes])
            text_parts.extend([attr.get("comment", "") for attr in parse_result.attributes])
            state.parsed["text"] = "\n".join(filter(None, text_parts))

            self.log_processing("MISP parsing complete", {"attributes": len(parse_result.attributes)})
            return state

        except Exception as e:
            self.logger.error(f"Error parsing MISP content: {e}")
            return self._fallback_to_text(state)

    def _fallback_to_text(self, state: GraphState) -> GraphState:
        """Fallback to text parsing on error."""
        content_bytes = base64.b64decode(state.fetched["content_b64"])
        state.parsed = {
            "type": "TEXT",
            "title": None,
            "text": content_bytes.decode('utf-8', errors='ignore')
        }
        return state


class STIXParseAgent(BaseAgent):
    """Agent for parsing STIX content."""

    def __init__(self):
        super().__init__("parse_stix")

    def get_system_prompt(self) -> str:
        return """You are a STIX 2.x bundle parser for CTI analysis.

Parse STIX bundle JSON and extract:
- Domain objects (indicators, malware, threat-actors, etc.)
- Relationships between objects
- Report metadata

Handle STIX 2.0 and 2.1 formats."""

    def process(self, state: GraphState) -> GraphState:
        try:
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            content_text = content_bytes.decode('utf-8', errors='ignore')

            # Parse as JSON
            stix_data = json.loads(content_text)
            parse_input = STIXParseInput(json=stix_data)
            parse_result = stix_parse_bundle(parse_input)

            state.parsed = {
                "type": "STIX",
                "objects": parse_result.objects,
                "relationships": parse_result.relationships,
                "report": parse_result.report
            }

            # Extract text for further processing
            text_parts = []
            if parse_result.report:
                text_parts.extend([
                    parse_result.report.get("name", ""),
                    parse_result.report.get("description", "")
                ])

            for obj in parse_result.objects:
                text_parts.extend([
                    obj.get("name", ""),
                    obj.get("description", "")
                ])

                # Extract STIX indicator patterns for IOC processing
                if obj.get("type") == "indicator" and obj.get("pattern"):
                    text_parts.append(f"STIX_INDICATOR_PATTERN: {obj.get('pattern')}")

            state.parsed["text"] = "\n".join(filter(None, text_parts))
            state.parsed["title"] = parse_result.report.get("name") if parse_result.report else None

            self.log_processing("STIX parsing complete", {"objects": len(parse_result.objects)})
            return state

        except Exception as e:
            self.logger.error(f"Error parsing STIX content: {e}")
            return self._fallback_to_text(state)

    def _fallback_to_text(self, state: GraphState) -> GraphState:
        """Fallback to text parsing on error."""
        content_bytes = base64.b64decode(state.fetched["content_b64"])
        state.parsed = {
            "type": "TEXT",
            "title": None,
            "text": content_bytes.decode('utf-8', errors='ignore')
        }
        return state


class RuleBasedHTMLParseAgent(BaseAgent):
    """Agent for parsing HTML content using rule-based approach."""

    def __init__(self):
        super().__init__("rule_based_parse_html")

    def get_system_prompt(self) -> str:
        return """You are an HTML content parser for CTI analysis using rule-based extraction.

Extract and convert HTML content to markdown:
- Use BeautifulSoup selectors for content identification
- Apply html2text for markdown conversion
- Extract metadata from HTML structure
- Remove navigation and non-content elements

This is the fast, consistent rule-based approach."""

    def process(self, state: GraphState) -> GraphState:
        try:
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            content_text = content_bytes.decode('utf-8', errors='ignore')

            parse_input = HTMLToMarkdownInput(html=content_text, url=state.url)
            parse_result = html_to_markdown(parse_input)

            state.parsed = {
                "type": "HTML",
                "title": parse_result.metadata.get("title"),
                "text": parse_result.markdown,
                "metadata": parse_result.metadata
            }
            state.markdown = parse_result.markdown

            self.log_processing("HTML parsing complete", {
                "markdown_chars": len(parse_result.markdown),
                "title": parse_result.metadata.get("title", "")[:50]
            })
            return state

        except Exception as e:
            self.logger.error(f"Error parsing HTML content: {e}")
            return self._fallback_to_text(state)

    def _fallback_to_text(self, state: GraphState) -> GraphState:
        """Fallback to text parsing on error."""
        content_bytes = base64.b64decode(state.fetched["content_b64"])
        state.parsed = {
            "type": "TEXT",
            "title": None,
            "text": content_bytes.decode('utf-8', errors='ignore')
        }
        return state


class HTMLParseAgent(BaseAgent):
    """Agent for parsing HTML content using LLM-based intelligent filtering."""

    def __init__(self):
        super().__init__("parse_html")

    def get_system_prompt(self) -> str:
        return """You are an advanced HTML content parser specialized in threat intelligence and cybersecurity content extraction.

OBJECTIVE: Convert HTML web content into clean, structured markdown while preserving essential information and removing clutter.

CONTENT SELECTION GUIDELINES:

1. Content Selection:
   - DO: Keep essential information, main content, key details
   - DO: Preserve hierarchical structure using markdown headers
   - DO: Keep code blocks, tables, key lists
   - DON'T: Include navigation menus, ads, footers, cookie notices
   - DON'T: Keep social media widgets, sidebars, related content

2. Content Transformation:
   - DO: Use proper markdown syntax (#, ##, **, `, etc)
   - DO: Convert tables to markdown tables
   - DO: Preserve code formatting with ```language blocks
   - DO: Maintain link texts but remove tracking parameters
   - DON'T: Include HTML tags in output
   - DON'T: Keep class names, ids, or other HTML attributes

3. Content Organization:
   - DO: Maintain logical flow of information
   - DO: Group related content under appropriate headers
   - DO: Use consistent header levels
   - DON'T: Fragment related content
   - DON'T: Duplicate information

4. Cybersecurity Focus:
   - DO: Preserve technical indicators (hashes, IPs, domains, CVEs)
   - DO: Keep threat actor names, malware families, attack techniques
   - DO: Maintain chronological information and attribution
   - DON'T: Remove security-relevant technical details

THREAT INTELLIGENCE FOCUS:
- Prioritize technical details, IOCs, CVE information, MITRE ATT&CK references
- Preserve security advisory structure and formatting
- Maintain attribution and source information
- Keep vulnerability details, patch information, and mitigation steps
- Preserve timeline information and incident details

QUALITY STANDARDS:
- Output clean, readable markdown suitable for analysis
- Maintain document structure and readability
- Preserve critical cybersecurity information
- Remove noise while keeping signal

IMPORTANT: Return ONLY the clean markdown content. Do not include explanations, HTML tags, or metadata."""

    def process(self, state: GraphState) -> GraphState:
        try:
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            html_content = content_bytes.decode('utf-8', errors='ignore')

            # Extract basic metadata first using BeautifulSoup
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract title
            title = None
            title_tag = soup.find("title")
            if title_tag:
                title = title_tag.get_text().strip()

            # Extract metadata
            metadata = {"title": title}
            meta_tags = soup.find_all("meta")
            for meta in meta_tags:
                name = meta.get("name", "").lower()
                content = meta.get("content", "")
                if name == "description":
                    metadata["description"] = content
                elif name == "author":
                    metadata["author"] = content

            # Use hybrid approach: rule-based pre-processing + LLM refinement
            markdown_content = self._hybrid_html_to_markdown(html_content)

            # If LLM returned very little content, fall back to rule-based approach
            if len(markdown_content.strip()) < 500:
                self.logger.warning(f"LLM returned only {len(markdown_content)} chars, falling back to rule-based parsing")
                markdown_content = self._fallback_html_to_markdown(html_content)

            state.parsed = {
                "type": "HTML",
                "title": title,
                "text": markdown_content,
                "metadata": metadata
            }
            state.markdown = markdown_content

            # Also store in extracted for final output
            if not hasattr(state, 'extracted') or not state.extracted:
                state.extracted = {}
            state.extracted["markdown"] = markdown_content

            # Debug: Log markdown content being saved
            self.logger.info(f"Setting state.markdown with {len(markdown_content)} characters")
            self.logger.info(f"Setting state.extracted['markdown'] with {len(markdown_content)} characters")
            self.logger.info(f"First 100 chars: {markdown_content[:100]}")

            self.log_processing("LLM HTML parsing complete", {
                "markdown_chars": len(markdown_content),
                "title": title[:50] if title else "None"
            })
            return state

        except Exception as e:
            self.logger.error(f"Error in LLM HTML parsing: {e}")
            return self._fallback_to_rule_based(state)

    def _hybrid_html_to_markdown(self, html_content: str) -> str:
        """Universal HTML processing: clean HTML + extract body + LLM filtering."""
        try:
            # Step 1: Clean HTML - remove scripts, styles, extract body content
            cleaned_html = self._clean_html_universally(html_content)

            # Step 2: Convert to text using html2text or BeautifulSoup
            initial_text = self._html_to_text(cleaned_html)

            # Step 3: Use LLM to intelligently filter and extract relevant content
            if len(initial_text) > 1000:  # Only use LLM for substantial content
                self.logger.info(f"Processing {len(initial_text)} chars with LLM filtering")

                # Chunk if too large
                if len(initial_text) > 50000:  # ~12K tokens
                    return self._chunk_and_filter_content(initial_text)
                else:
                    return self._llm_filter_content(initial_text)
            else:
                self.logger.info(f"Content too small ({len(initial_text)} chars), using as-is")
                return initial_text

        except Exception as e:
            self.logger.error(f"Universal HTML processing failed: {e}")
            return self._fallback_html_to_markdown(html_content)

    def _clean_html_universally(self, html_content: str) -> str:
        """Clean HTML by removing scripts, styles and extracting body content."""
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, "html.parser")

            # Remove script, style, noscript tags
            for tag in soup(["script", "style", "noscript", "iframe", "embed", "object"]):
                tag.decompose()

            # Remove HTML comments
            from bs4 import Comment
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            for comment in comments:
                comment.extract()

            # Extract body content, fallback to entire document if no body
            body = soup.find("body")
            if body:
                return str(body)
            else:
                return str(soup)

        except Exception as e:
            self.logger.warning(f"HTML cleaning failed: {e}, using original content")
            return html_content

    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract text with some structure preservation
            text = soup.get_text(separator='\n', strip=True)

            # Clean up excessive whitespace
            import re
            text = re.sub(r'\n{3,}', '\n\n', text)  # Max 2 newlines
            text = re.sub(r'[ \t]+', ' ', text)     # Normalize spaces

            return text.strip()

        except Exception as e:
            self.logger.warning(f"HTML to text conversion failed: {e}")
            return html_content

    def _llm_filter_content(self, text_content: str) -> str:
        """Use LLM to filter and extract relevant content."""
        try:
            prompt = f"""Extract and clean the main article content from this web page text for cyber threat intelligence analysis.

TASK: Return only the main article content as clean markdown, removing:
- Navigation menus, headers, footers
- Advertisements and promotional content
- Social media widgets and comment sections
- Newsletter signups and related articles
- Cookie notices and disclaimers

PRESERVE: All technical details, threat actor names, malware names, CVEs, IOCs, attack methods, and factual information.

FORMAT: Return clean markdown with proper headers, lists, and structure.

CONTENT TO FILTER:
{text_content}"""

            filtered_content = self.call_llm(self.get_system_prompt(), prompt)

            if len(filtered_content.strip()) > 200:  # Reasonable content threshold
                self.logger.info(f"LLM filtering successful: {len(filtered_content)} chars")
                return filtered_content
            else:
                self.logger.warning("LLM filtering returned too little content, using original")
                return text_content

        except Exception as e:
            self.logger.error(f"LLM filtering failed: {e}")
            return text_content

    def _chunk_and_filter_content(self, text_content: str) -> str:
        """Process large content in chunks and combine results."""
        try:
            chunk_size = 40000  # ~10K tokens per chunk
            chunks = []

            # Split into chunks
            for i in range(0, len(text_content), chunk_size):
                chunk = text_content[i:i + chunk_size]
                chunks.append(chunk)

            # Process each chunk
            filtered_chunks = []
            for i, chunk in enumerate(chunks[:5]):  # Limit to 5 chunks for cost control
                try:
                    self.logger.info(f"Processing chunk {i+1}/{min(len(chunks), 5)}: {len(chunk)} chars")
                    filtered_chunk = self._llm_filter_content(chunk)
                    filtered_chunks.append(filtered_chunk)
                except Exception as e:
                    self.logger.warning(f"Chunk {i+1} processing failed: {e}, using original")
                    filtered_chunks.append(chunk)

            # Combine chunks
            combined_content = "\n\n".join(filtered_chunks)

            self.logger.info(f"Chunked processing complete: {len(combined_content)} chars from {len(filtered_chunks)} chunks")
            return combined_content

        except Exception as e:
            self.logger.error(f"Chunked processing failed: {e}")
            return text_content

    def _llm_html_to_markdown(self, html_content: str) -> str:
        """Use LLM to intelligently convert HTML to markdown."""
        try:
            # Chunk content if too large (roughly 8000 tokens = ~32KB)
            if len(html_content) > 32000:
                return self._chunk_and_process_html(html_content)

            # Single LLM call for smaller content
            prompt = f"""Convert this HTML content to clean markdown following the guidelines:

{html_content}

Return only the clean markdown content."""

            # Use BaseAgent's call_llm method
            markdown_content = self.call_llm(self.get_system_prompt(), prompt)

            # Debug: Log what LLM returned
            self.logger.info(f"LLM returned markdown content: {len(markdown_content)} chars")
            self.logger.info(f"First 200 chars: {markdown_content[:200]}")

            self.log_processing("LLM HTML conversion", {
                "prompt_tokens": self.token_usage["prompt_tokens"],
                "completion_tokens": self.token_usage["completion_tokens"],
                "total_tokens": self.token_usage["total_tokens"]
            })

            return markdown_content

        except Exception as e:
            self.logger.error(f"LLM HTML conversion failed: {e}")
            # Fallback to rule-based approach
            return self._fallback_html_to_markdown(html_content)

    def _chunk_and_process_html(self, html_content: str) -> str:
        """Process large HTML content in chunks."""
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, "html.parser")

            # Find semantic boundaries for chunking
            chunks = []

            # Try to chunk by semantic elements
            for element in soup.find_all(['article', 'section', 'div'], limit=10):
                element_html = str(element)
                if len(element_html) > 5000 and len(element_html) < 30000:
                    chunks.append(element_html)

            # If no good chunks found, fall back to simple text splitting
            if not chunks:
                # Split by approximate token size
                chunk_size = 25000  # Roughly 6000 tokens
                for i in range(0, len(html_content), chunk_size):
                    chunks.append(html_content[i:i + chunk_size])

            # Process each chunk
            markdown_parts = []
            for i, chunk in enumerate(chunks[:5]):  # Limit to 5 chunks for cost control
                try:
                    prompt = f"""Convert this HTML content chunk to clean markdown following the guidelines:

{chunk}

Return only the clean markdown content."""

                    # Use BaseAgent's call_llm method
                    chunk_markdown = self.call_llm(self.get_system_prompt(), prompt)
                    self.logger.info(f"Chunk {i}: {len(chunk_markdown)} chars")
                    markdown_parts.append(chunk_markdown)

                except Exception as e:
                    self.logger.warning(f"Failed to process chunk {i}: {e}")
                    continue

            # Combine chunks
            combined_markdown = "\n\n".join(markdown_parts)

            self.log_processing("Chunked LLM HTML processing", {
                "chunks_processed": len(markdown_parts),
                "total_chunks": len(chunks),
                "final_markdown_chars": len(combined_markdown)
            })

            return combined_markdown

        except Exception as e:
            self.logger.error(f"Chunked processing failed: {e}")
            return self._fallback_html_to_markdown(html_content)

    def _fallback_html_to_markdown(self, html_content: str) -> str:
        """Fallback to rule-based HTML parsing."""
        try:
            from ...tools.parsers.html_to_markdown import html_to_markdown, HTMLToMarkdownInput

            parse_input = HTMLToMarkdownInput(html=html_content, url="")
            parse_result = html_to_markdown(parse_input)

            self.logger.info("Fell back to rule-based HTML parsing")
            return parse_result.markdown

        except Exception as e:
            self.logger.error(f"Fallback HTML parsing failed: {e}")
            # Ultimate fallback: try to extract any text
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            return soup.get_text(separator="\n", strip=True)

    def _fallback_to_rule_based(self, state: GraphState) -> GraphState:
        """Fallback to rule-based HTML parsing on error."""
        try:
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            content_text = content_bytes.decode('utf-8', errors='ignore')

            from ...tools.parsers.html_to_markdown import html_to_markdown, HTMLToMarkdownInput
            parse_input = HTMLToMarkdownInput(html=content_text, url=state.url)
            parse_result = html_to_markdown(parse_input)

            state.parsed = {
                "type": "HTML_FALLBACK",
                "title": parse_result.metadata.get("title"),
                "text": parse_result.markdown,
                "metadata": parse_result.metadata
            }
            state.markdown = parse_result.markdown

            self.log_processing("Fallback to rule-based HTML parsing", {
                "markdown_chars": len(parse_result.markdown)
            })
            return state

        except Exception as e:
            self.logger.error(f"Even fallback HTML parsing failed: {e}")
            return self._fallback_to_text(state)

    def _fallback_to_text(self, state: GraphState) -> GraphState:
        """Ultimate fallback to text parsing on error."""
        content_bytes = base64.b64decode(state.fetched["content_b64"])
        state.parsed = {
            "type": "TEXT",
            "title": None,
            "text": content_bytes.decode('utf-8', errors='ignore')
        }
        return state


class PDFParseAgent(BaseAgent):
    """Agent for parsing PDF content using enhanced MCP tool."""

    def __init__(self):
        super().__init__("parse_pdf")

    def get_system_prompt(self) -> str:
        return """You are a PDF parser for Cyber Threat Intelligence (CTI) analysis using enhanced extraction.

Extract comprehensive content from PDF documents:
- Full text with layout preservation
- Markdown conversion for structured content
- Generate title from document content (analyze first few lines to identify the main title/heading)
- Metadata extraction (author, dates, but ignore metadata title)
- Image and table detection
- Security information analysis

IMPORTANT: Generate the document title by analyzing the actual content text, not from PDF metadata. Look for the main heading or title in the first few lines of the document content.

Focus on threat intelligence reports and security advisories."""

    def process(self, state: GraphState) -> GraphState:
        try:
            from ...tools.pdf_extract import extract_pdf_text_and_markup, PDFExtractInput

            # Use the enhanced MCP PDF extraction tool
            pdf_input = PDFExtractInput(
                content_b64=state.fetched["content_b64"],
                preserve_layout=True,
                include_metadata=True,
                extract_images=True
            )

            pdf_result = extract_pdf_text_and_markup(pdf_input)

            if pdf_result.success:
                # Use content-based title generation (will be handled by LLM processing)
                # Extract first few lines for title generation
                content_preview = pdf_result.full_text[:2000] if pdf_result.full_text else ""

                # Populate state with comprehensive PDF data
                state.parsed = {
                    "type": "PDF",
                    "text": pdf_result.full_text,
                    "title": None,  # Will be generated from content by downstream processing
                    "content_preview": content_preview,  # Add preview for title generation
                    "pages": pdf_result.total_pages,
                    "metadata": pdf_result.metadata,
                    "page_details": [
                        {
                            "page_num": page.page_num,
                            "text": page.text,
                            "markdown": page.markdown,
                            "images": len(page.images),
                            "tables": len(page.tables)
                        }
                        for page in pdf_result.pages
                    ]
                }

                # Set markdown for further processing
                state.markdown = pdf_result.full_markdown

                # Add PDF-specific evidence
                evidence = {
                    "type": "pdf_extraction",
                    "source": "PDF document analysis",
                    "details": {
                        "total_pages": pdf_result.total_pages,
                        "text_length": len(pdf_result.full_text),
                        "images_found": sum(len(page.images) for page in pdf_result.pages),
                        "tables_found": sum(len(page.tables) for page in pdf_result.pages),
                        "metadata": pdf_result.metadata,
                        "security_info": pdf_result.security_info
                    }
                }
                state.evidence.append(evidence)

                self.log_processing(
                    "PDF parsing complete",
                    {
                        "pages": pdf_result.total_pages,
                        "text_chars": len(pdf_result.full_text),
                        "markdown_chars": len(pdf_result.full_markdown),
                        "images": sum(len(page.images) for page in pdf_result.pages)
                    }
                )
                return state

            else:
                self.logger.error(f"PDF extraction failed: {pdf_result.error}")
                return self._fallback_to_text(state)

        except Exception as e:
            self.logger.error(f"Error parsing PDF content: {e}")
            return self._fallback_to_text(state)

    def _fallback_to_text(self, state: GraphState) -> GraphState:
        """Fallback to text parsing on error."""
        content_bytes = base64.b64decode(state.fetched["content_b64"])
        state.parsed = {
            "type": "TEXT",
            "title": None,
            "text": content_bytes.decode('utf-8', errors='ignore')
        }
        return state


class JSONParseAgent(BaseAgent):
    """Agent for parsing generic JSON content."""

    def __init__(self):
        super().__init__("parse_json")

    def get_system_prompt(self) -> str:
        return """You are a generic JSON parser for CTI analysis.

Parse JSON content and extract:
- Readable text representation
- Flattened key-value structure
- Key information summary

Handle various JSON structures gracefully."""

    def process(self, state: GraphState) -> GraphState:
        try:
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            content_text = content_bytes.decode('utf-8', errors='ignore')

            json_data = json.loads(content_text)
            parse_input = JSONNormalizeInput(obj=json_data)
            parse_result = json_normalize(parse_input)

            state.parsed = {
                "type": "JSON",
                "title": None,
                "text": parse_result.text,
                "flat": parse_result.flat
            }

            self.log_processing("JSON parsing complete", {"text_chars": len(parse_result.text)})
            return state

        except Exception as e:
            self.logger.error(f"Error parsing JSON content: {e}")
            return self._fallback_to_text(state)

    def _fallback_to_text(self, state: GraphState) -> GraphState:
        """Fallback to text parsing on error."""
        content_bytes = base64.b64decode(state.fetched["content_b64"])
        state.parsed = {
            "type": "TEXT",
            "title": None,
            "text": content_bytes.decode('utf-8', errors='ignore')
        }
        return state


class TextParseAgent(BaseAgent):
    """Agent for parsing plain text content."""

    def __init__(self):
        super().__init__("parse_text")

    def get_system_prompt(self) -> str:
        return """You are a plain text parser for CTI analysis.

Handle plain text content:
- Clean encoding issues
- Preserve structure
- Extract basic metadata if possible

This is the fallback parser for unknown content types."""

    def process(self, state: GraphState) -> GraphState:
        try:
            content_bytes = base64.b64decode(state.fetched["content_b64"])
            content_text = content_bytes.decode('utf-8', errors='ignore')

            # Convert plain text to basic markdown format
            markdown_content = self._text_to_markdown(content_text)

            state.parsed = {
                "type": "TEXT",
                "title": None,
                "text": content_text
            }
            state.markdown = markdown_content

            self.log_processing("Text parsing complete", {
                "text_chars": len(content_text),
                "markdown_chars": len(markdown_content)
            })
            return state

        except Exception as e:
            self.logger.error(f"Error parsing text content: {e}")
            state.parsed = {
                "type": "TEXT",
                "title": None,
                "text": f"Text parsing error: {str(e)}"
            }
            return state

    def _text_to_markdown(self, text: str) -> str:
        """Convert plain text to basic markdown format."""
        try:
            import re

            lines = text.split('\n')
            markdown_lines = []

            for line in lines:
                line = line.strip()

                # Skip empty lines
                if not line:
                    markdown_lines.append('')
                    continue

                # Convert headers (lines that are ALL CAPS or title case)
                if len(line) > 5 and line.isupper() and not any(char in line for char in '.,!?'):
                    markdown_lines.append(f"## {line.title()}")
                elif re.match(r'^[A-Z][A-Za-z\s]+:?\s*$', line) and len(line) < 50:
                    markdown_lines.append(f"### {line}")

                # Convert bullet points
                elif re.match(r'^\s*[-*•]\s+', line):
                    cleaned_line = re.sub(r'^\s*[-*•]\s+', '', line)
                    markdown_lines.append(f"- {cleaned_line}")

                # Convert numbered lists
                elif re.match(r'^\s*\d+[\.)]\s+', line):
                    cleaned_line = re.sub(r'^\s*\d+[\.)]\s+', '', line)
                    markdown_lines.append(f"1. {cleaned_line}")

                # Convert URLs to markdown links
                elif re.search(r'https?://[^\s]+', line):
                    # Make URLs clickable
                    url_line = re.sub(r'(https?://[^\s]+)', r'[\1](\1)', line)
                    markdown_lines.append(url_line)

                # Regular text paragraphs
                else:
                    markdown_lines.append(line)

            # Join and clean up
            markdown_content = '\n'.join(markdown_lines)

            # Clean up excessive newlines
            markdown_content = re.sub(r'\n{4,}', '\n\n\n', markdown_content)

            return markdown_content.strip()

        except Exception as e:
            self.logger.warning(f"Error converting text to markdown: {e}")
            # Fallback: just return the original text
            return text