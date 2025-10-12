"""Storage and emit functionality."""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class StoreInput(BaseModel):
    """Input for storage tool."""

    json_data: Dict[str, Any] = Field(description="JSON object to store", alias="json")
    path: Optional[str] = Field(description="Local file path to write")
    s3: Optional[Dict[str, str]] = Field(description="S3 storage config {bucket, key}")


class StoreOutput(BaseModel):
    """Output for storage tool."""

    written: bool = Field(description="Whether storage succeeded")
    locator: str = Field(description="Storage location identifier")


def write_json_file(data: Dict[str, Any], file_path: str) -> bool:
    """Write JSON data to local file."""
    try:
        # Ensure directory exists
        path_obj = Path(file_path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)

        # Write JSON with pretty formatting
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)

        file_size = os.path.getsize(file_path)
        logger.info(f"Wrote JSON to file: {file_path} ({file_size} bytes)")

        # Print user-visible success message
        print(f"✅ CTI artifact saved to: {os.path.abspath(file_path)} ({file_size:,} bytes)")
        return True

    except Exception as e:
        logger.error(f"Error writing JSON file {file_path}: {e}")
        return False


def upload_to_s3(data: Dict[str, Any], bucket: str, key: str) -> bool:
    """Upload JSON data to S3."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError

        # Create S3 client
        s3_client = boto3.client('s3')

        # Convert to JSON bytes
        json_bytes = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True).encode('utf-8')

        # Upload with metadata
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=json_bytes,
            ContentType='application/json',
            ContentEncoding='utf-8',
            Metadata={
                'cti-pipeline': 'agentic-cti',
                'format': 'json',
                'size': str(len(json_bytes))
            }
        )

        logger.info(f"Uploaded JSON to S3: s3://{bucket}/{key} ({len(json_bytes)} bytes)")
        return True

    except ImportError:
        logger.error("boto3 not available for S3 upload")
        return False
    except NoCredentialsError:
        logger.error("AWS credentials not configured for S3 upload")
        return False
    except ClientError as e:
        logger.error(f"S3 upload error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected S3 upload error: {e}")
        return False


def generate_default_path(data: Dict[str, Any]) -> str:
    """Generate default file path based on data."""
    # Try to get SHA-256 hash from URL for filename
    url = data.get("url", "")
    sha256 = None

    # Extract hash from URL if available (assumed to be in memory system)
    try:
        from urllib.parse import urlparse
        from ..memory import get_memory_system

        memory = get_memory_system()
        canonical_url = data.get("url", "")

        # Try to find content hash from memory
        with memory.get_session() as session:
            from ..memory import ContentRecord
            record = session.query(ContentRecord).filter_by(url=canonical_url).first()
            if record:
                sha256 = record.sha256

    except Exception:
        pass

    # Generate filename
    if sha256:
        filename = f"{sha256}.json"
    else:
        # Fallback: use timestamp
        import time
        timestamp = int(time.time())
        filename = f"cti_{timestamp}.json"

    # Get output directory from environment or default
    output_dir = os.getenv("OUTPUT_DIR", "./out")
    return os.path.join(output_dir, filename)


def store_emit(input_data: StoreInput) -> StoreOutput:
    """Store JSON data to specified location."""
    try:
        data = input_data.json_data
        local_path = input_data.path
        s3_config = input_data.s3

        written = False
        locators = []

        # Store to local file
        if local_path:
            file_path = local_path
        else:
            # Generate default path
            file_path = generate_default_path(data)

        if write_json_file(data, file_path):
            written = True
            locators.append(f"file://{os.path.abspath(file_path)}")

        # Store to S3 if configured
        if s3_config and isinstance(s3_config, dict):
            bucket = s3_config.get("bucket", "")
            key = s3_config.get("key", "")

            if bucket and key:
                if upload_to_s3(data, bucket, key):
                    written = True
                    locators.append(f"s3://{bucket}/{key}")

        # Return primary locator
        primary_locator = locators[0] if locators else f"file://{os.path.abspath(file_path)}"

        # Update memory system with artifact path
        if written and locators:
            try:
                from ..memory import get_memory_system
                from ..dedup import compute_content_hash

                memory = get_memory_system()
                url = data.get("url", "")

                if url:
                    # Compute content hash for the JSON artifact
                    json_str = json.dumps(data, sort_keys=True)
                    content_hash = compute_content_hash(json_str.encode('utf-8'))

                    # Update artifact path in memory
                    memory.update_artifact_path(content_hash, primary_locator)

            except Exception as e:
                logger.warning(f"Failed to update memory with artifact path: {e}")

        logger.info(f"Storage result: written={written}, locator={primary_locator}")

        return StoreOutput(
            written=written,
            locator=primary_locator
        )

    except Exception as e:
        logger.error(f"Error in storage: {e}")
        return StoreOutput(
            written=False,
            locator="error://storage-failed"
        )


# Tool registration for MCP
TOOL_NAME = "store.emit"
TOOL_DESCRIPTION = "Store JSON data to file system or S3"
INPUT_SCHEMA = StoreInput.model_json_schema()
OUTPUT_SCHEMA = StoreOutput.model_json_schema()