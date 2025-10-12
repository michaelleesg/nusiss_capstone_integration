"""MCP tool for PDF text extraction and markup conversion."""

import base64
import logging
import re
from typing import List, Optional

import fitz  # PyMuPDF
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PDFExtractInput(BaseModel):
    """Input for PDF text extraction."""
    content_b64: str = Field(description="Base64 encoded PDF content")
    page_range: Optional[str] = Field(default=None, description="Page range (e.g., '1-5', '1,3,5')")
    extract_images: bool = Field(default=False, description="Extract image metadata")
    preserve_layout: bool = Field(default=True, description="Preserve document layout")
    include_metadata: bool = Field(default=True, description="Include document metadata")


class PDFPage(BaseModel):
    """Extracted PDF page information."""
    page_num: int = Field(description="Page number (1-based)")
    text: str = Field(description="Extracted text content")
    markdown: str = Field(description="Text converted to markdown")
    images: List[dict] = Field(default_factory=list, description="Image metadata")
    tables: List[dict] = Field(default_factory=list, description="Table information")


class PDFExtractOutput(BaseModel):
    """Output from PDF text extraction."""
    success: bool = Field(description="Whether extraction succeeded")
    pages: List[PDFPage] = Field(default_factory=list, description="Extracted pages")
    metadata: dict = Field(default_factory=dict, description="Document metadata")
    total_pages: int = Field(description="Total number of pages")
    full_text: str = Field(description="Combined text from all pages")
    full_markdown: str = Field(description="Combined markdown from all pages")
    security_info: dict = Field(default_factory=dict, description="PDF security information")
    error: Optional[str] = Field(default=None, description="Error message if failed")


def extract_pdf_text_and_markup(input_data: PDFExtractInput) -> PDFExtractOutput:
    """
    Extract text from PDF and convert to markdown format.

    This MCP tool provides comprehensive PDF processing:
    - Text extraction with layout preservation
    - Conversion to clean markdown format
    - Metadata extraction
    - Image and table detection
    - Security info analysis
    """
    doc = None
    try:
        # Decode base64 PDF content
        pdf_bytes = base64.b64decode(input_data.content_b64)

        # Open PDF document with error handling
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        # Check if document is valid
        if doc.page_count == 0:
            raise ValueError("PDF document has no pages")

        # Extract metadata safely
        metadata = {}
        try:
            doc_metadata = doc.metadata or {}
            metadata = {
                "title": doc_metadata.get("title", ""),
                "author": doc_metadata.get("author", ""),
                "subject": doc_metadata.get("subject", ""),
                "creator": doc_metadata.get("creator", ""),
                "producer": doc_metadata.get("producer", ""),
                "creation_date": doc_metadata.get("creationDate", ""),
                "modification_date": doc_metadata.get("modDate", ""),
                "keywords": doc_metadata.get("keywords", ""),
            }
        except Exception as e:
            logger.warning(f"Could not extract metadata: {e}")
            metadata = {}

        # Security information
        security_info = {}
        try:
            security_info = {
                "encrypted": getattr(doc, 'is_encrypted', False),
                "needs_password": getattr(doc, 'needs_pass', False),
                "permissions": getattr(doc, 'permissions', None),
            }
        except Exception as e:
            logger.warning(f"Could not extract security info: {e}")

        # Store total pages before processing
        total_pages = doc.page_count

        # Parse page range
        page_numbers = _parse_page_range(input_data.page_range, total_pages)

        pages = []
        full_text = ""
        full_markdown = ""

        # Process each page
        for page_num in page_numbers:
            try:
                # Get page with bounds checking
                if page_num - 1 >= total_pages:
                    logger.warning(f"Page {page_num} exceeds document page count {total_pages}")
                    continue

                page = doc[page_num - 1]  # PyMuPDF uses 0-based indexing

                # Extract text with layout preservation
                text = ""
                structured_text = ""

                try:
                    if input_data.preserve_layout:
                        text = page.get_text("text") or ""
                        blocks = page.get_text("dict")
                        structured_text = _extract_structured_text(blocks) if blocks else text
                    else:
                        text = page.get_text() or ""
                        structured_text = text
                except Exception as e:
                    logger.warning(f"Error extracting text from page {page_num}: {e}")
                    text = f"Error extracting text from page {page_num}"
                    structured_text = text

                # Convert to markdown
                try:
                    markdown = _text_to_markdown(structured_text, page)
                except Exception as e:
                    logger.warning(f"Error converting to markdown on page {page_num}: {e}")
                    markdown = structured_text

                # Extract images if requested
                images = []
                if input_data.extract_images:
                    try:
                        images = _extract_image_info(page)
                    except Exception as e:
                        logger.warning(f"Error extracting images from page {page_num}: {e}")

                # Detect tables
                tables = []
                try:
                    tables = _detect_tables(page)
                except Exception as e:
                    logger.warning(f"Error detecting tables on page {page_num}: {e}")

                page_info = PDFPage(
                    page_num=page_num,
                    text=text,
                    markdown=markdown,
                    images=images,
                    tables=tables
                )

                pages.append(page_info)
                full_text += f"\n\n--- Page {page_num} ---\n\n{text}"
                full_markdown += f"\n\n## Page {page_num}\n\n{markdown}"

            except Exception as e:
                logger.warning(f"Error processing page {page_num}: {e}")
                # Add a placeholder for failed pages
                error_page = PDFPage(
                    page_num=page_num,
                    text=f"Error processing page {page_num}: {str(e)}",
                    markdown=f"## Page {page_num} (Error)\n\nError processing page: {str(e)}",
                    images=[],
                    tables=[]
                )
                pages.append(error_page)
                continue

        # Clean up full text and markdown
        full_text = _clean_text(full_text)
        full_markdown = _clean_markdown(full_markdown)

        return PDFExtractOutput(
            success=True,
            pages=pages,
            metadata=metadata,
            total_pages=total_pages,
            full_text=full_text,
            full_markdown=full_markdown,
            security_info=security_info
        )

    except Exception as e:
        logger.error(f"PDF extraction failed: {e}")
        return PDFExtractOutput(
            success=False,
            pages=[],
            metadata={},
            total_pages=0,
            full_text="",
            full_markdown="",
            security_info={},
            error=str(e)
        )
    finally:
        # Ensure document is closed even if there are errors
        if doc is not None:
            try:
                doc.close()
            except Exception as e:
                logger.warning(f"Error closing document: {e}")


def _parse_page_range(page_range: Optional[str], total_pages: int) -> List[int]:
    """Parse page range specification."""
    if not page_range:
        return list(range(1, total_pages + 1))

    pages = []

    # Handle comma-separated ranges and individual pages
    parts = page_range.split(',')

    for part in parts:
        part = part.strip()

        if '-' in part:
            # Range: "1-5"
            start, end = part.split('-', 1)
            start = int(start.strip())
            end = int(end.strip())
            pages.extend(range(start, min(end + 1, total_pages + 1)))
        else:
            # Individual page: "3"
            page_num = int(part)
            if 1 <= page_num <= total_pages:
                pages.append(page_num)

    return sorted(list(set(pages)))


def _extract_structured_text(blocks: dict) -> str:
    """Extract structured text from PyMuPDF text blocks."""
    text_parts = []

    for block in blocks.get("blocks", []):
        if "lines" in block:
            for line in block["lines"]:
                line_text = ""
                for span in line.get("spans", []):
                    span_text = span.get("text", "")
                    # Preserve formatting hints
                    if span.get("flags", 0) & 2**4:  # Bold
                        span_text = f"**{span_text}**"
                    if span.get("flags", 0) & 2**1:  # Italic
                        span_text = f"*{span_text}*"
                    line_text += span_text

                if line_text.strip():
                    text_parts.append(line_text)

    return "\n".join(text_parts)


def _text_to_markdown(text: str, page) -> str:
    """Convert extracted text to markdown format."""
    lines = text.split('\n')
    markdown_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            markdown_lines.append("")
            continue

        # Detect headers (larger font size, centered, or specific patterns)
        if _is_header(line):
            # Determine header level based on content
            if any(word in line.upper() for word in ['EXECUTIVE', 'SUMMARY', 'CONCLUSION']):
                markdown_lines.append(f"## {line}")
            elif line.isupper() and len(line) < 60:
                markdown_lines.append(f"### {line}")
            else:
                markdown_lines.append(f"#### {line}")

        # Detect bullet points
        elif _is_bullet_point(line):
            cleaned_line = re.sub(r'^[•·▪▫◦‣⁃\-\*]\s*', '', line)
            markdown_lines.append(f"- {cleaned_line}")

        # Detect numbered lists
        elif re.match(r'^\d+[\.\)]\s+', line):
            cleaned_line = re.sub(r'^\d+[\.\)]\s+', '', line)
            markdown_lines.append(f"1. {cleaned_line}")

        # Regular paragraph
        else:
            markdown_lines.append(line)

    return '\n'.join(markdown_lines)


def _is_header(line: str) -> bool:
    """Detect if a line is likely a header."""
    if len(line) > 100:  # Too long for header
        return False

    # Common header patterns
    header_patterns = [
        r'^[A-Z][A-Z\s]{2,}$',  # ALL CAPS
        r'^\d+\.\s+[A-Z]',       # Numbered sections
        r'^(CHAPTER|SECTION|PART)\s+\d+',  # Chapter/Section markers
        r'^(ABSTRACT|INTRODUCTION|BACKGROUND|METHODOLOGY|RESULTS|DISCUSSION|CONCLUSION)',
    ]

    return any(re.match(pattern, line.upper()) for pattern in header_patterns)


def _is_bullet_point(line: str) -> bool:
    """Detect if a line is a bullet point."""
    bullet_chars = ['•', '·', '▪', '▫', '◦', '‣', '⁃', '-', '*']
    return any(line.startswith(char) for char in bullet_chars)


def _extract_image_info(page) -> List[dict]:
    """Extract image metadata from a page."""
    images = []

    try:
        image_list = page.get_images()

        for img_index, img in enumerate(image_list):
            xref = img[0]
            img_dict = page.parent.extract_image(xref)

            images.append({
                "index": img_index,
                "xref": xref,
                "width": img_dict.get("width", 0),
                "height": img_dict.get("height", 0),
                "colorspace": img_dict.get("colorspace", ""),
                "ext": img_dict.get("ext", ""),
                "size": len(img_dict.get("image", b"")),
            })

    except Exception as e:
        logger.warning(f"Error extracting image info: {e}")

    return images


def _detect_tables(page) -> List[dict]:
    """Detect table structures in a page."""
    tables = []

    try:
        # Simple table detection based on text alignment
        text_dict = page.get_text("dict")

        # Look for patterns that suggest tabular data
        for block in text_dict.get("blocks", []):
            if "lines" in block:
                lines = block["lines"]

                # Check for consistent spacing/alignment
                if len(lines) >= 3:  # Minimum rows for a table
                    x_positions = []
                    for line in lines[:5]:  # Check first 5 lines
                        for span in line.get("spans", []):
                            x_positions.append(span.get("bbox", [0])[0])

                    # If we have consistent column positions, it might be a table
                    if len(set(round(x, 0) for x in x_positions)) >= 2:
                        tables.append({
                            "bbox": block.get("bbox", []),
                            "estimated_columns": len(set(round(x, 0) for x in x_positions)),
                            "estimated_rows": len(lines),
                        })

    except Exception as e:
        logger.warning(f"Error detecting tables: {e}")

    return tables


def _clean_text(text: str) -> str:
    """Clean extracted text."""
    # Remove excessive whitespace
    text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)
    text = re.sub(r'[ \t]+', ' ', text)

    # Remove page markers
    text = re.sub(r'\n--- Page \d+ ---\n', '\n\n', text)

    return text.strip()


def _clean_markdown(markdown: str) -> str:
    """Clean generated markdown."""
    # Remove excessive newlines
    markdown = re.sub(r'\n{3,}', '\n\n', markdown)

    # Clean up headers
    markdown = re.sub(r'^#+\s*$', '', markdown, flags=re.MULTILINE)

    return markdown.strip()


# Register the tool for MCP
def get_tool_info():
    """Get tool information for MCP registration."""
    return {
        "name": "pdf_extract",
        "description": "Extract text from PDF and convert to markdown format",
        "input_schema": PDFExtractInput.model_json_schema(),
        "output_schema": PDFExtractOutput.model_json_schema(),
    }