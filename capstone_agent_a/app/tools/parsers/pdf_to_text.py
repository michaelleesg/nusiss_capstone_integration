"""PDF to text converter."""

import base64
import logging
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PDFToTextInput(BaseModel):
    """Input for PDF to text converter."""

    pdf_b64: str = Field(description="Base64-encoded PDF content")


class PDFToTextOutput(BaseModel):
    """Output for PDF to text converter."""

    text: str = Field(description="Extracted text content")


def extract_text_with_pymupdf(pdf_bytes: bytes) -> str:
    """Extract text using PyMuPDF."""
    try:
        import fitz  # PyMuPDF

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        text_parts = []

        for page_num in range(doc.page_count):
            page = doc.load_page(page_num)
            text = page.get_text()
            if text.strip():
                text_parts.append(f"--- Page {page_num + 1} ---\n{text}")

        doc.close()
        return "\n\n".join(text_parts)

    except ImportError:
        logger.warning("PyMuPDF not available, falling back to pdfminer")
        raise
    except Exception as e:
        logger.error(f"PyMuPDF extraction failed: {e}")
        raise


def extract_text_with_pdfminer(pdf_bytes: bytes) -> str:
    """Extract text using pdfminer.six."""
    try:
        from pdfminer.high_level import extract_text
        from io import BytesIO

        pdf_file = BytesIO(pdf_bytes)
        text = extract_text(pdf_file)
        return text

    except ImportError:
        logger.warning("pdfminer.six not available")
        raise
    except Exception as e:
        logger.error(f"pdfminer extraction failed: {e}")
        raise


def clean_pdf_text(text: str) -> str:
    """Clean and normalize extracted PDF text."""
    import re

    # Remove excessive whitespace
    text = re.sub(r"\s+", " ", text)

    # Fix common PDF extraction artifacts
    text = re.sub(r"(\w)-\s+(\w)", r"\1\2", text)  # Remove hyphenation across lines
    text = re.sub(r"\s*\n\s*", "\n", text)  # Clean line breaks
    text = re.sub(r"\n{3,}", "\n\n", text)  # Limit consecutive newlines

    # Remove page numbers and headers/footers (simple heuristic)
    lines = text.split("\n")
    cleaned_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip lines that look like page numbers
        if re.match(r"^\d+$", line) and len(line) <= 3:
            continue

        # Skip very short lines at start/end (likely headers/footers)
        if len(line) < 10 and (not cleaned_lines or len(cleaned_lines) < 3):
            continue

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip()


def pdf_to_text(input_data: PDFToTextInput) -> PDFToTextOutput:
    """Convert PDF to text."""
    try:
        # Decode base64 PDF
        pdf_bytes = base64.b64decode(input_data.pdf_b64)

        if not pdf_bytes:
            raise ValueError("Empty PDF data")

        # Verify PDF header
        if not pdf_bytes.startswith(b"%PDF"):
            raise ValueError("Invalid PDF format")

        extracted_text = ""

        # Try PyMuPDF first
        try:
            extracted_text = extract_text_with_pymupdf(pdf_bytes)
            logger.info(f"Extracted text using PyMuPDF: {len(extracted_text)} chars")
        except Exception as e:
            logger.warning(f"PyMuPDF failed: {e}")

            # Fallback to pdfminer
            try:
                extracted_text = extract_text_with_pdfminer(pdf_bytes)
                logger.info(f"Extracted text using pdfminer: {len(extracted_text)} chars")
            except Exception as e2:
                logger.error(f"All PDF extraction methods failed: {e2}")
                raise ValueError("Could not extract text from PDF")

        # Clean the extracted text
        cleaned_text = clean_pdf_text(extracted_text)

        if not cleaned_text.strip():
            logger.warning("No text extracted from PDF")
            cleaned_text = "[Empty PDF or text extraction failed]"

        logger.info(f"PDF text extraction complete: {len(cleaned_text)} chars")

        return PDFToTextOutput(text=cleaned_text)

    except Exception as e:
        logger.error(f"Error converting PDF to text: {e}")
        return PDFToTextOutput(text=f"Error: {str(e)}")


# Tool registration for MCP
TOOL_NAME = "pdf.to_text"
TOOL_DESCRIPTION = "Extract text content from PDF"
INPUT_SCHEMA = PDFToTextInput.model_json_schema()
OUTPUT_SCHEMA = PDFToTextOutput.model_json_schema()