"""Text processing utilities for LLM input management."""

import json
import logging
import os
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


# Token limit configuration from environment variables
def get_token_limit(agent_type: str) -> int:
    """Get token limit for specific agent type from environment."""
    env_mapping = {
        "summarize": "LLM_SUMMARIZE_MAX_TOKENS",
        "entity": "LLM_ENTITY_MAX_TOKENS",
        "ioc": "LLM_IOC_MAX_TOKENS",
        "cve": "LLM_CVE_MAX_TOKENS",
        "mitre": "LLM_MITRE_MAX_TOKENS",
        "geo_motivation": "LLM_GEO_MOTIVATION_MAX_TOKENS",
        "cyber": "LLM_CYBER_MAX_TOKENS",
        "general": "LLM_DEFAULT_MAX_TOKENS"
    }

    # Default values as fallback
    defaults = {
        "summarize": 3500,
        "entity": 4000,
        "ioc": 3500,
        "cve": 3500,
        "mitre": 3500,
        "geo_motivation": 3500,
        "cyber": 3000,
        "general": 3500
    }

    env_var = env_mapping.get(agent_type, "LLM_DEFAULT_MAX_TOKENS")
    default_value = defaults.get(agent_type, 3500)

    try:
        return int(os.getenv(env_var, default_value))
    except (ValueError, TypeError):
        logger.warning(f"Invalid token limit in {env_var}, using default: {default_value}")
        return default_value


def get_overlap_tokens() -> int:
    """Get overlap tokens for chunking from environment."""
    try:
        return int(os.getenv("LLM_OVERLAP_TOKENS", 200))
    except (ValueError, TypeError):
        logger.warning("Invalid LLM_OVERLAP_TOKENS, using default: 200")
        return 200


def get_summary_max_tokens() -> int:
    """Get maximum tokens for summary generation from environment."""
    try:
        return int(os.getenv("LLM_SUMMARY_MAX_TOKENS", 500))
    except (ValueError, TypeError):
        logger.warning("Invalid LLM_SUMMARY_MAX_TOKENS, using default: 500")
        return 500


def estimate_tokens(text: str) -> int:
    """
    Estimate token count for text using a more accurate method.
    Based on OpenAI's guidance: ~4 characters per token for English text.
    """
    # More sophisticated estimation considering:
    # - Punctuation and special characters
    # - Common patterns in CTI text

    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text.strip())

    # Count words and characters
    words = len(text.split())
    chars = len(text)

    # Estimate tokens: average of word-based and character-based estimates
    word_based_estimate = words * 1.3  # CTI text tends to have technical terms
    char_based_estimate = chars / 3.5  # Slightly more conservative than 4 chars/token

    return int((word_based_estimate + char_based_estimate) / 2)


def intelligent_truncate(text: str, max_tokens: int = 3000, preserve_structure: bool = True) -> str:
    """
    Intelligently truncate text to fit within token limits while preserving important information.

    Args:
        text: Input text to truncate
        max_tokens: Maximum tokens to allow
        preserve_structure: Whether to try to preserve document structure
    """
    if not text.strip():
        return text

    current_tokens = estimate_tokens(text)

    if current_tokens <= max_tokens:
        return text

    logger.info(f"Text truncation needed: {current_tokens} tokens -> {max_tokens} tokens")

    if preserve_structure:
        return _structure_aware_truncate(text, max_tokens)
    else:
        return _simple_truncate(text, max_tokens)


def _structure_aware_truncate(text: str, max_tokens: int) -> str:
    """Truncate text while preserving document structure."""
    lines = text.split('\n')

    # Prioritize different types of content
    priority_lines = []
    normal_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # High priority: headers, IOCs, CVEs, threat actor names
        if (line.isupper() or  # Headers
            re.search(r'\bCVE-\d{4}-\d+\b', line) or  # CVEs
            re.search(r'\b(?:APT|UNC)\d+\b', line, re.IGNORECASE) or  # Threat actors
            re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line) or  # IPs
            re.search(r'\b[a-fA-F0-9]{32,64}\b', line) or  # Hashes
            re.search(r'https?://[^\s]+', line)):
            priority_lines.append(line)
        else:
            normal_lines.append(line)

    # Build result starting with priority content
    result_lines = []
    current_tokens = 0

    # Add priority lines first
    for line in priority_lines:
        line_tokens = estimate_tokens(line)
        if current_tokens + line_tokens <= max_tokens:
            result_lines.append(line)
            current_tokens += line_tokens
        else:
            break

    # Add normal lines if space remaining
    for line in normal_lines:
        line_tokens = estimate_tokens(line)
        if current_tokens + line_tokens <= max_tokens:
            result_lines.append(line)
            current_tokens += line_tokens
        else:
            # Try to add a truncated version of this line
            remaining_tokens = max_tokens - current_tokens
            if remaining_tokens > 50:  # Only if meaningful space left
                truncated_line = _simple_truncate(line, remaining_tokens)
                if truncated_line.strip():
                    result_lines.append(truncated_line + "...")
            break

    return '\n'.join(result_lines)


def _simple_truncate(text: str, max_tokens: int) -> str:
    """Simple truncation based on token estimation."""
    current_tokens = estimate_tokens(text)

    if current_tokens <= max_tokens:
        return text

    # Calculate approximate character limit
    ratio = max_tokens / current_tokens
    char_limit = int(len(text) * ratio * 0.95)  # 5% buffer

    # Truncate at word boundary
    truncated = text[:char_limit]
    last_space = truncated.rfind(' ')
    if last_space > char_limit * 0.8:  # If we found a reasonable word boundary
        truncated = truncated[:last_space]

    return truncated


def chunk_by_paragraphs(text: str, max_tokens_per_chunk: int = None) -> List[str]:
    """
    Smart paragraph-based chunking that preserves semantic coherence.

    Args:
        text: Text to chunk
        max_tokens_per_chunk: Maximum tokens per chunk (uses env default if None)
    """
    if max_tokens_per_chunk is None:
        max_tokens_per_chunk = get_token_limit("general")

    total_tokens = estimate_tokens(text)
    if total_tokens <= max_tokens_per_chunk:
        return [text]

    # Split by paragraph boundaries (double newlines)
    paragraphs = re.split(r'\n\s*\n', text)
    chunks = []
    current_chunk = []
    current_tokens = 0

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        para_tokens = estimate_tokens(para)

        # If single paragraph is too large, split it by sentences
        if para_tokens > max_tokens_per_chunk:
            if current_chunk:
                chunks.append('\n\n'.join(current_chunk))
                current_chunk = []
                current_tokens = 0

            # Split large paragraph by sentences
            sentences = re.split(r'[.!?]+', para)
            sentence_chunk = []
            sentence_tokens = 0

            for sentence in sentences:
                sentence = sentence.strip()
                if not sentence:
                    continue

                sent_tokens = estimate_tokens(sentence)
                if sentence_tokens + sent_tokens <= max_tokens_per_chunk:
                    sentence_chunk.append(sentence)
                    sentence_tokens += sent_tokens
                else:
                    if sentence_chunk:
                        chunks.append('. '.join(sentence_chunk) + '.')
                    sentence_chunk = [sentence]
                    sentence_tokens = sent_tokens

            if sentence_chunk:
                chunks.append('. '.join(sentence_chunk) + '.')
            continue

        # Check if adding this paragraph exceeds limit
        if current_tokens + para_tokens <= max_tokens_per_chunk:
            current_chunk.append(para)
            current_tokens += para_tokens
        else:
            # Finalize current chunk and start new one
            if current_chunk:
                chunks.append('\n\n'.join(current_chunk))
            current_chunk = [para]
            current_tokens = para_tokens

    # Add the last chunk
    if current_chunk:
        chunks.append('\n\n'.join(current_chunk))

    logger.info(f"Text chunked by paragraphs into {len(chunks)} chunks (avg {total_tokens // len(chunks)} tokens each)")
    return chunks


def classify_cybersecurity_relevance(chunk: str) -> Dict[str, Any]:
    """
    Use LLM to classify if chunk contains cybersecurity-relevant information.

    Returns:
        Dict with relevance_score (1-10) and key_elements list
    """
    # Validate chunk for jailbreak attempts before LLM processing
    from .guardrails_helper import get_cti_guardrails
    guardrails = get_cti_guardrails()

    if not guardrails.is_content_safe(chunk, "cyber_classifier"):
        logger.warning("Chunk blocked by guardrails in classification")
        return _fallback_classification(chunk)

    classifier_prompt = """You are a cybersecurity content classifier. Analyze the text chunk and rate its cybersecurity relevance.

Rating scale 1-10:
- 10: Critical cyber content (IOCs, CVEs, active threats, malware analysis)
- 8-9: High cyber content (threat actor TTPs, attack campaigns, incidents)
- 6-7: Medium cyber content (vulnerabilities, security recommendations)
- 4-5: Low cyber content (general IT/tech with minor security relevance)
- 1-3: Non-cyber content (background, financial, organizational info)

CRITICAL: Respond ONLY with valid JSON. No explanation, no markdown, no extra text.

Required format: {"relevance_score": 8, "key_elements": ["CVE-2023-1234", "APT28", "malware"]}"""

    try:
        # Use OpenAI client directly to avoid BaseAgent abstract class issues
        import os
        from openai import OpenAI

        if not os.getenv("OPENAI_API_KEY"):
            logger.warning("No OPENAI_API_KEY found, using fallback classification")
            return _fallback_classification(chunk)

        client = OpenAI(timeout=30.0, max_retries=1)

        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": classifier_prompt},
                {"role": "user", "content": f"Text chunk to analyze:\n\n{chunk}"}
            ],
            temperature=0.1,
            max_tokens=500  # Small response needed for classification
        )

        content = response.choices[0].message.content

        if not content or content.strip() == "":
            logger.warning("LLM returned empty response, using fallback classification")
            return _fallback_classification(chunk)

        # Clean up response - extract JSON if wrapped in markdown
        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        # Try to parse JSON
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from text response
            import re
            json_match = re.search(r'\{[^{}]*"relevance_score"[^{}]*\}', content)
            if json_match:
                try:
                    result = json.loads(json_match.group())
                except json.JSONDecodeError:
                    logger.warning(f"Could not parse extracted JSON: {json_match.group()}")
                    return _fallback_classification(chunk)
            else:
                logger.warning(f"No valid JSON found in response: {content[:100]}...")
                return _fallback_classification(chunk)

        # Validate response structure
        if "relevance_score" not in result:
            result["relevance_score"] = 5  # Default to medium relevance
        if "key_elements" not in result:
            result["key_elements"] = []

        # Ensure score is in valid range
        score = result["relevance_score"]
        if not isinstance(score, (int, float)) or score < 1 or score > 10:
            result["relevance_score"] = 5

        return result

    except Exception as e:
        logger.warning(f"Error in cybersecurity classification: {e}")
        # Fallback: use regex-based heuristics
        return _fallback_classification(chunk)


def _fallback_classification(chunk: str) -> Dict[str, Any]:
    """Fallback classification using regex patterns when LLM fails."""
    cyber_patterns = {
        'high_priority': [
            r'\bCVE-\d{4}-\d+\b',  # CVEs
            r'\b(?:APT|UNC|TA)\d+\b',  # Threat actors
            r'\b[a-fA-F0-9]{32,64}\b',  # Hashes
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IPs
            r'https?://[^\s]+',  # URLs
        ],
        'medium_priority': [
            r'\b(?:malware|trojan|ransomware|backdoor|exploit)\b',
            r'\b(?:phishing|spearphishing|c2|command.and.control)\b',
            r'\b(?:vulnerability|zero.day|patch|mitigation)\b',
        ],
        'low_priority': [
            r'\b(?:security|cyber|attack|threat|breach)\b',
            r'\b(?:firewall|antivirus|detection|monitoring)\b',
        ]
    }

    chunk_lower = chunk.lower()
    key_elements = []
    score = 1

    # Check for high priority patterns
    for pattern in cyber_patterns['high_priority']:
        matches = re.findall(pattern, chunk, re.IGNORECASE)
        if matches:
            key_elements.extend(matches[:3])  # Limit to 3 per pattern
            score = max(score, 8)

    # Check for medium priority patterns
    for pattern in cyber_patterns['medium_priority']:
        matches = re.findall(pattern, chunk, re.IGNORECASE)
        if matches:
            key_elements.extend(matches[:2])
            score = max(score, 6)

    # Check for low priority patterns
    for pattern in cyber_patterns['low_priority']:
        if re.search(pattern, chunk_lower):
            score = max(score, 4)

    return {
        "relevance_score": score,
        "key_elements": list(set(key_elements))  # Remove duplicates
    }


def summarize_relevant_chunks(chunks: List[str], relevance_threshold: int = 6) -> str:
    """
    Filter chunks by cybersecurity relevance and summarize the relevant ones.

    Args:
        chunks: List of text chunks
        relevance_threshold: Minimum relevance score (1-10) to include chunk

    Returns:
        Summarized text of relevant chunks
    """
    relevant_chunks = []
    classification_results = []

    logger.info(f"Classifying {len(chunks)} chunks for cybersecurity relevance...")

    for i, chunk in enumerate(chunks):
        classification = classify_cybersecurity_relevance(chunk)
        classification_results.append(classification)

        score = classification["relevance_score"]
        if score >= relevance_threshold:
            relevant_chunks.append(chunk)
            logger.debug(f"Chunk {i+1}: Relevant (score={score}) - {classification['key_elements'][:3]}")
        else:
            logger.debug(f"Chunk {i+1}: Filtered out (score={score})")

    if not relevant_chunks:
        logger.warning("No cybersecurity-relevant chunks found above threshold")
        return "No cybersecurity-relevant content found in the document."

    logger.info(f"Selected {len(relevant_chunks)}/{len(chunks)} chunks as cybersecurity-relevant")

    # Combine relevant chunks
    combined_text = '\n\n--- CHUNK SEPARATOR ---\n\n'.join(relevant_chunks)

    # If combined text is still too long, create a context summary
    combined_tokens = estimate_tokens(combined_text)
    max_tokens = get_token_limit("general")

    if combined_tokens <= max_tokens:
        return combined_text
    else:
        logger.info(f"Combined relevant chunks ({combined_tokens} tokens) exceed limit, creating summary")
        return create_context_summary(combined_text, max_tokens)


def chunk_text(text: str, max_tokens_per_chunk: int = None, overlap_tokens: int = None) -> List[str]:
    """
    Legacy chunking function - kept for backward compatibility.
    Consider using chunk_by_paragraphs() for better semantic coherence.
    """
    if max_tokens_per_chunk is None:
        max_tokens_per_chunk = get_token_limit("general")
    if overlap_tokens is None:
        overlap_tokens = get_overlap_tokens()

    total_tokens = estimate_tokens(text)

    if total_tokens <= max_tokens_per_chunk:
        return [text]

    chunks = []
    sentences = re.split(r'[.!?]+', text)

    current_chunk = []
    current_tokens = 0

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue

        sentence_tokens = estimate_tokens(sentence)

        # If single sentence is too long, truncate it
        if sentence_tokens > max_tokens_per_chunk:
            sentence = intelligent_truncate(sentence, max_tokens_per_chunk, preserve_structure=False)
            sentence_tokens = estimate_tokens(sentence)

        # If adding this sentence would exceed limit, start new chunk
        if current_tokens + sentence_tokens > max_tokens_per_chunk and current_chunk:
            chunks.append('. '.join(current_chunk) + '.')

            # Start new chunk with overlap
            overlap_sentences = []
            overlap_tokens_count = 0
            for prev_sentence in reversed(current_chunk):
                prev_tokens = estimate_tokens(prev_sentence)
                if overlap_tokens_count + prev_tokens <= overlap_tokens:
                    overlap_sentences.insert(0, prev_sentence)
                    overlap_tokens_count += prev_tokens
                else:
                    break

            current_chunk = overlap_sentences
            current_tokens = overlap_tokens_count

        current_chunk.append(sentence)
        current_tokens += sentence_tokens

    # Add the last chunk
    if current_chunk:
        chunks.append('. '.join(current_chunk) + '.')

    logger.info(f"Text chunked into {len(chunks)} chunks (avg {total_tokens // len(chunks)} tokens each)")
    return chunks


def create_context_summary(text: str, max_summary_tokens: int = None) -> str:
    """
    Create a brief summary of very long text to preserve context.
    This is useful when text is too long even for chunking.
    """
    if max_summary_tokens is None:
        max_summary_tokens = get_summary_max_tokens()

    if estimate_tokens(text) <= max_summary_tokens * 2:
        return text

    # Extract key information for summary
    key_patterns = {
        'threat_actors': r'\b(?:APT|UNC|TA)\d+\b',
        'malware': r'\b\w*(?:trojan|malware|ransomware|backdoor|loader)\w*\b',
        'cves': r'\bCVE-\d{4}-\d+\b',
        'iocs': r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9]{32,64}|https?://[^\s]+)\b',
        'techniques': r'\bT\d{4}(?:\.\d{3})?\b'
    }

    summary_parts = []

    # Extract title/header if present
    lines = text.split('\n')
    if lines:
        first_line = lines[0].strip()
        if len(first_line) < 200 and (first_line.isupper() or any(c.isupper() for c in first_line[:20])):
            summary_parts.append(f"Title: {first_line}")

    # Extract key entities
    for category, pattern in key_patterns.items():
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        if matches:
            summary_parts.append(f"{category.replace('_', ' ').title()}: {', '.join(matches)}")

    # Add truncated content
    remaining_tokens = max_summary_tokens - estimate_tokens('\n'.join(summary_parts))
    if remaining_tokens > 100:
        content_summary = intelligent_truncate(text, remaining_tokens, preserve_structure=True)
        summary_parts.append(f"Content excerpt: {content_summary}")

    return '\n'.join(summary_parts)


def prepare_llm_input(text: str, agent_type: str = "general", max_input_tokens: int = None) -> Dict[str, Any]:
    """
    Prepare text for LLM input with intelligent processing based on agent type.

    Uses new 3-step approach:
    1. Chunk by paragraphs if text is too large
    2. Filter chunks using LLM-based cybersecurity classification
    3. Summarize relevant chunks if needed

    Args:
        text: Input text
        agent_type: Type of agent (affects processing strategy)
        max_input_tokens: Maximum tokens for LLM input (uses env config if None)

    Returns:
        Dict containing processed text and metadata
    """
    if max_input_tokens is None:
        max_input_tokens = get_token_limit(agent_type)

    if not text.strip():
        return {
            "text": "",
            "processing_strategy": "empty",
            "original_tokens": 0,
            "processed_tokens": 0,
            "chunks": 0,
            "relevant_chunks": 0,
            "max_tokens_configured": max_input_tokens
        }

    original_tokens = estimate_tokens(text)

    # Strategy 1: Text fits within limits, use as-is
    if original_tokens <= max_input_tokens:
        return {
            "text": text,
            "processing_strategy": "full",
            "original_tokens": original_tokens,
            "processed_tokens": original_tokens,
            "chunks": 1,
            "relevant_chunks": 1,
            "max_tokens_configured": max_input_tokens
        }

    # Strategy 2: Moderate length, use intelligent truncation
    elif original_tokens <= max_input_tokens * 1.5:
        processed_text = intelligent_truncate(text, max_input_tokens, preserve_structure=True)
        return {
            "text": processed_text,
            "processing_strategy": "truncated",
            "original_tokens": original_tokens,
            "processed_tokens": estimate_tokens(processed_text),
            "chunks": 1,
            "relevant_chunks": 1,
            "max_tokens_configured": max_input_tokens
        }

    # Strategy 3: Large text - use new 3-step approach
    else:
        logger.info(f"Large text ({original_tokens} tokens) - using chunk+classify+summarize approach")

        # Step 1: Chunk by paragraphs
        chunks = chunk_by_paragraphs(text, max_input_tokens // 2)  # Smaller chunks for classification

        # Step 2: Filter for cybersecurity relevance
        # Use lower threshold for summarization agents to capture more context
        relevance_threshold = 5 if agent_type in ["summarize", "cyber"] else 6
        processed_text = summarize_relevant_chunks(chunks, relevance_threshold)

        # Count relevant chunks for metadata
        relevant_count = 0
        for chunk in chunks:
            classification = classify_cybersecurity_relevance(chunk)
            if classification["relevance_score"] >= relevance_threshold:
                relevant_count += 1

        return {
            "text": processed_text,
            "processing_strategy": "chunked_classified_summarized",
            "original_tokens": original_tokens,
            "processed_tokens": estimate_tokens(processed_text),
            "chunks": len(chunks),
            "relevant_chunks": relevant_count,
            "relevance_threshold": relevance_threshold,
            "max_tokens_configured": max_input_tokens
        }