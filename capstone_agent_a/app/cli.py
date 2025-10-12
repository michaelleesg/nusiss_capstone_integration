"""CLI interface for the CTI pipeline."""

import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

import click
from dotenv import load_dotenv

# Lazy imports to avoid 111s+ startup delays from heavy ML libraries
from .logging_conf import setup_logging
from .memory import get_memory_system


@click.group()
@click.option('--log-level', default='INFO', help='Log level (DEBUG, INFO, WARNING, ERROR)')
@click.option('--env-file', default='.env', help='Environment file path')
def cli(log_level: str, env_file: str):
    """Agentic CTI URL→JSON pipeline."""
    # Load environment
    if os.path.exists(env_file):
        load_dotenv(env_file)

    # Setup logging
    setup_logging(log_level)


@cli.command()
@click.argument('urls', nargs=-1, required=True)
@click.option('--file', '-f', 'url_file', help='File containing URLs (one per line)')
@click.option('--output-dir', default='./out', help='Output directory for artifacts')
@click.option('--auth-username', help='Username for HTTP basic authentication')
@click.option('--auth-password', help='Password for HTTP basic authentication')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification (insecure)')
@click.option('--bypass-memory', is_flag=True, help='Bypass memory check and reprocess URLs even if already processed')
def run(urls: tuple, url_file: Optional[str], output_dir: str, auth_username: Optional[str], auth_password: Optional[str], no_ssl_verify: bool, bypass_memory: bool):
    """Process URLs through the CTI pipeline."""
    logger = logging.getLogger(__name__)

    # Collect URLs
    all_urls = list(urls)

    if url_file:
        try:
            with open(url_file, 'r') as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                all_urls.extend(file_urls)
        except FileNotFoundError:
            logger.error(f"URL file not found: {url_file}")
            sys.exit(1)

    if not all_urls:
        logger.error("No URLs provided")
        sys.exit(1)

    # Ensure output directory exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    os.environ['OUTPUT_DIR'] = output_dir

    logger.info(f"Processing {len(all_urls)} URLs with agentic processing")

    # Process URLs with agentic processing
    results = []
    errors = 0

    from .graph import process_url  # Lazy import

    for i, url in enumerate(all_urls, 1):
        logger.info(f"Processing {i}/{len(all_urls)}: {url}")
        try:
            result = process_url(url, auth_username=auth_username, auth_password=auth_password, verify_ssl=not no_ssl_verify, bypass_memory=bypass_memory)

            # Handle RSS feeds (list of results) vs single URLs (single result)
            if result.get('is_rss_feed', False) and result.get('results'):
                # RSS feed with multiple items
                rss_results = result['results']
                logger.info(f"RSS feed processed: {len(rss_results)} items")
                logger.info(f"DEBUG: First RSS item keys: {list(rss_results[0].keys()) if rss_results else 'No items'}")
                logger.info(f"DEBUG: First RSS item success: {rss_results[0].get('success') if rss_results else 'N/A'}")
                logger.info(f"DEBUG: First RSS item has data: {bool(rss_results[0].get('data')) if rss_results else 'N/A'}")

                for item_idx, item_result in enumerate(rss_results, 1):
                    results.append(item_result)
                    output_result(item_result)

                    # Note: RSS items are saved immediately by the orchestrator during processing
                    # No need to save again here to avoid duplicates

                    if not item_result.get('success', False):
                        errors += 1

                # Print RSS feed summary
                feed_meta = result.get('feed_metadata', {})
                print(f"📡 RSS Feed '{feed_meta.get('title', url)}': {feed_meta.get('successful_count', 0)} successful, {feed_meta.get('failed_count', 0)} failed")

            else:
                # Single URL result
                results.append(result)
                output_result(result)

                # Save JSON artifact if processing was successful
                if result.get('success', False) and result.get('data'):
                    try:
                        from .tools.store_emit import store_emit, StoreInput
                        store_input = StoreInput(json=result['data'], path=None, s3=None)
                        store_result = store_emit(store_input)

                        if store_result.written:
                            if store_result.locator.startswith("file://"):
                                file_path = store_result.locator[7:]
                                print(f"📁 CTI JSON saved to: {file_path}")
                        else:
                            logger.warning(f"Failed to save CTI artifact for {url}")
                    except Exception as save_error:
                        logger.error(f"Error saving CTI artifact for {url}: {save_error}")

                if not result.get('success', False):
                    errors += 1

        except Exception as e:
            logger.error(f"Failed to process {url}: {e}")
            error_result = {
                "url": url,
                "success": False,
                "error": str(e),
                "sha256": "",
                "artifact": "",
                "short_circuit": False,
                "summary": ""
            }
            results.append(error_result)
            output_result(error_result)
            errors += 1

    # Summary
    successful = len(results) - errors
    logger.info(f"Processing complete: {successful}/{len(results)} successful, {errors} errors")

    # Calculate total token usage across all URLs
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_tokens = 0
    total_processing_time = 0.0

    for result in results:
        if result.get('token_usage'):
            token_usage = result['token_usage']
            total_prompt_tokens += token_usage.get('prompt_tokens', token_usage.get('input_tokens', 0))
            total_completion_tokens += token_usage.get('completion_tokens', token_usage.get('output_tokens', 0))
            total_tokens += token_usage.get('total_tokens', 0)
            total_processing_time += token_usage.get('processing_time', 0.0)

    if total_tokens > 0:
        print(f"\n🔢 Total Token Usage Summary:")
        print(f"   📝 Total prompt tokens: {total_prompt_tokens:,}")
        print(f"   💭 Total completion tokens: {total_completion_tokens:,}")
        print(f"   📊 Total tokens: {total_tokens:,}")
        if total_processing_time > 0:
            print(f"   ⏱️  Total processing time: {total_processing_time:.2f}s")

        # Show total cost estimate based on model
        model = os.getenv("LLM_MODEL", "gpt-4o-mini")

        # Pricing as of 2024 (per 1K tokens)
        if "gpt-4o-mini" in model.lower():
            input_price = 0.00015   # $0.150 per 1M tokens
            output_price = 0.0006   # $0.600 per 1M tokens
        elif "gpt-4o" in model.lower():
            input_price = 0.005     # $5.00 per 1M tokens
            output_price = 0.015    # $15.00 per 1M tokens
        elif "gpt-4-turbo" in model.lower():
            input_price = 0.01      # $10.00 per 1M tokens
            output_price = 0.03     # $30.00 per 1M tokens
        elif "gpt-3.5-turbo" in model.lower():
            input_price = 0.0005    # $0.50 per 1M tokens
            output_price = 0.0015   # $1.50 per 1M tokens
        else:
            # Default to gpt-4o-mini pricing
            input_price = 0.00015
            output_price = 0.0006

        prompt_cost = total_prompt_tokens * input_price / 1000
        completion_cost = total_completion_tokens * output_price / 1000
        total_cost = prompt_cost + completion_cost
        print(f"   💰 Total estimated cost ({model}): ${total_cost:.4f}")

    if errors > 0:
        sys.exit(1)


def output_result(result: dict) -> None:
    """Output result summary to stdout."""
    # Determine artifact path
    artifact = ""
    short_circuit = False

    if result.get('success') and result.get('data'):
        # Try to find artifact path from data
        url = result['url']
        sha256 = result.get('sha256', '')

        if sha256:
            # Check if stored
            memory = get_memory_system()
            with memory.get_session() as session:
                from .memory import ContentRecord
                record = session.query(ContentRecord).filter_by(sha256=sha256).first()
                if record and record.artifact_path:
                    artifact = record.artifact_path
                    short_circuit = True

    # Extract summary
    summary = ""
    if result.get('data') and isinstance(result['data'], dict):
        summary = result['data'].get('summary', '')[:200]

    # Output JSON line
    output = {
        "url": result.get('url', ''),
        "sha256": result.get('sha256', ''),
        "artifact": artifact,
        "short_circuit": short_circuit,
        "summary": summary
    }

    print(json.dumps(output, separators=(',', ':')))


@cli.command()
@click.option('--reset', is_flag=True, help='Reset the database')
def db(reset: bool):
    """Database management."""
    logger = logging.getLogger(__name__)

    memory = get_memory_system()

    if reset:
        logger.info("Resetting database...")
        # Drop all tables and recreate
        from .memory import Base
        Base.metadata.drop_all(memory.engine)
        Base.metadata.create_all(memory.engine)
        logger.info("Database reset complete")
    else:
        # Show stats
        with memory.get_session() as session:
            from .memory import ContentRecord, IOCIndex, CVEIndex
            content_count = session.query(ContentRecord).count()
            ioc_count = session.query(IOCIndex).count()
            cve_count = session.query(CVEIndex).count()

            logger.info(f"Database stats:")
            logger.info(f"  Content records: {content_count}")
            logger.info(f"  IOC index entries: {ioc_count}")
            logger.info(f"  CVE index entries: {cve_count}")


@cli.command()
@click.argument('input_file')
@click.option('--pretty', is_flag=True, help='Pretty print JSON')
def validate(input_file: str, pretty: bool):
    """Validate CTI artifact JSON schema."""
    logger = logging.getLogger(__name__)

    try:
        with open(input_file, 'r') as f:
            data = json.load(f)

        from .tools.schema_validate import validate_and_heal, SchemaInput
        from .state import CTIArtifact

        # Validate against CTI schema
        schema = CTIArtifact.model_json_schema()
        validation_input = SchemaInput(json=data, schema=schema)
        result = validate_and_heal(validation_input)

        if result.ok:
            logger.info("✓ Validation passed")
        else:
            logger.warning(f"⚠ Validation issues found: {len(result.errors)} errors")
            for error in result.errors:
                logger.warning(f"  Path: {'.'.join(map(str, error['path']))}")
                logger.warning(f"  Error: {error['message']}")

        if pretty:
            print(json.dumps(result.healed, indent=2))
        else:
            print(json.dumps(result.healed))

    except FileNotFoundError:
        logger.error(f"File not found: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {input_file}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Validation error: {e}")
        sys.exit(1)


@cli.command()
@click.option('--transport', type=click.Choice(['stdio', 'tcp']), default='stdio', help='Transport type')
@click.option('--host', default='127.0.0.1', help='IP address for TCP transport')
@click.option('--port', type=int, default=8765, help='Port for TCP transport')
def mcp_server(transport: str, host: str, port: int):
    """Start MCP server."""
    from .mcp_server.server import MCPServer
    from .logging_conf import setup_logging
    import logging
    import sys

    # Setup logging to stderr so it doesn't interfere with JSON-RPC on stdout
    setup_logging()

    # Redirect default logging to stderr for stdio transport
    if transport == "stdio":
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.INFO)
            if hasattr(handler, 'stream') and handler.stream == sys.stdout:
                handler.setStream(sys.stderr)

    server = MCPServer(
        transport_type=transport,
        host=host,
        port=port
    )
    server.run()


@cli.command()
def mcp_demo():
    """Demonstrate MCP client/server."""
    from .mcp_server.client import demo_client
    demo_client()


@cli.command()
@click.option('--url', help='Test with specific URL')
@click.option('--sample-data', is_flag=True, help='Use sample test data')
@click.option('--auth-username', help='Username for HTTP basic authentication')
@click.option('--auth-password', help='Password for HTTP basic authentication')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification (insecure)')
def test(url: Optional[str], sample_data: bool, auth_username: Optional[str], auth_password: Optional[str], no_ssl_verify: bool):
    """Test the pipeline with sample data."""
    logger = logging.getLogger(__name__)

    if url:
        # Process URL using hybrid agentic-parallel mode
        logger.info(f"Testing with URL: {url}")
        try:
            from .graph import process_url
            result = process_url(url, auth_username=auth_username, auth_password=auth_password, verify_ssl=not no_ssl_verify)

            # Handle RSS feeds vs single URLs
            if result.get('is_rss_feed', False) and result.get('results'):
                # RSS feed with multiple items
                rss_results = result['results']
                logger.info(f"RSS feed test: {len(rss_results)} items")

                success_count = 0
                for item_idx, item_result in enumerate(rss_results, 1):
                    output_result(item_result)

                    # Save each RSS item as separate JSON artifact
                    if item_result.get('success', False) and item_result.get('data'):
                        try:
                            from .tools.store_emit import store_emit, StoreInput
                            import time

                            # Generate unique filename for RSS item
                            timestamp = int(time.time())
                            output_dir = os.getenv("OUTPUT_DIR", "./out")
                            rss_filename = f"cti_{timestamp}_{item_idx}.json"
                            rss_path = os.path.join(output_dir, rss_filename)

                            store_input = StoreInput(json=item_result['data'], path=rss_path, s3=None)
                            store_result = store_emit(store_input)

                            if store_result.written:
                                if store_result.locator.startswith("file://"):
                                    file_path = store_result.locator[7:]
                                    item_title = item_result.get('item_metadata', {}).get('title', 'RSS Item')[:50]
                                    print(f"📁 RSS Item saved: {item_title}... -> {file_path}")
                            else:
                                logger.warning(f"Failed to save RSS item: {item_result.get('url')}")
                        except Exception as save_error:
                            logger.error(f"Error saving RSS item: {save_error}")
                        success_count += 1

                feed_meta = result.get('feed_metadata', {})
                print(f"📡 RSS Test Complete: {success_count}/{len(rss_results)} items successful")

                if success_count > 0:
                    logger.info("✓ RSS Test passed")
                else:
                    logger.error("✗ RSS Test failed: no items processed successfully")
                    sys.exit(1)

            else:
                # Single URL result
                output_result(result)

                # Save JSON artifact if processing was successful
                if result.get('success', False) and result.get('data'):
                    try:
                        from .tools.store_emit import store_emit, StoreInput
                        store_input = StoreInput(json=result['data'], path=None, s3=None)
                        store_result = store_emit(store_input)

                        if store_result.written:
                            if store_result.locator.startswith("file://"):
                                file_path = store_result.locator[7:]
                                print(f"📁 CTI JSON saved to: {file_path}")
                        else:
                            logger.warning(f"Failed to save CTI artifact for {url}")
                    except Exception as save_error:
                        logger.error(f"Error saving CTI artifact for {url}: {save_error}")

                # Display token usage summary
                if result.get('token_usage'):
                    token_usage = result['token_usage']
                    prompt_tokens = token_usage.get('prompt_tokens', token_usage.get('input_tokens', 0))
                    completion_tokens = token_usage.get('completion_tokens', token_usage.get('output_tokens', 0))
                    total_tokens = token_usage.get('total_tokens', prompt_tokens + completion_tokens)
                    processing_time = token_usage.get('processing_time', 0.0)

                    print(f"🔢 Token Usage Summary:")
                    print(f"   📝 Prompt tokens: {prompt_tokens:,}")
                    print(f"   💭 Completion tokens: {completion_tokens:,}")
                    print(f"   📊 Total tokens: {total_tokens:,}")
                    if processing_time > 0:
                        print(f"   ⏱️  Processing time: {processing_time:.2f}s")

                    # Show cost estimate if tokens were used
                    if total_tokens > 0:
                        model = os.getenv("LLM_MODEL", "gpt-4o-mini")

                        # Pricing as of 2024 (per 1K tokens)
                        if "gpt-4o-mini" in model.lower():
                            input_price = 0.00015   # $0.150 per 1M tokens
                            output_price = 0.0006   # $0.600 per 1M tokens
                        elif "gpt-4o" in model.lower():
                            input_price = 0.005     # $5.00 per 1M tokens
                            output_price = 0.015    # $15.00 per 1M tokens
                        elif "gpt-4-turbo" in model.lower():
                            input_price = 0.01      # $10.00 per 1M tokens
                            output_price = 0.03     # $30.00 per 1M tokens
                        elif "gpt-3.5-turbo" in model.lower():
                            input_price = 0.0005    # $0.50 per 1M tokens
                            output_price = 0.0015   # $1.50 per 1M tokens
                        else:
                            # Default to gpt-4o-mini pricing
                            input_price = 0.00015
                            output_price = 0.0006

                        prompt_cost = prompt_tokens * input_price / 1000
                        completion_cost = completion_tokens * output_price / 1000
                        total_cost = prompt_cost + completion_cost
                        print(f"   💰 Estimated cost ({model}): ${total_cost:.4f}")

                if result.get('success'):
                    logger.info("✓ Test passed")
                else:
                    logger.error(f"✗ Test failed: {result.get('error')}")
                    sys.exit(1)

        except Exception as e:
            logger.error(f"Test failed: {e}")
            sys.exit(1)

    elif sample_data:
        # Test with sample URLs
        test_urls = [
            "https://www.cisa.gov/uscert/ncas/alerts/aa23-215a",
            "https://www.virustotal.com",
            "https://feeds.feedburner.com/eset/blog"
        ]

        from .graph import process_url  # Lazy import

        logger.info(f"Testing with {len(test_urls)} sample URLs")
        for test_url in test_urls:
            logger.info(f"Testing: {test_url}")
            try:
                result = process_url(test_url, auth_username=auth_username, auth_password=auth_password, verify_ssl=not no_ssl_verify)

                # Handle RSS feeds vs single URLs
                if result.get('is_rss_feed', False) and result.get('results'):
                    # RSS feed with multiple items
                    rss_results = result['results']
                    logger.info(f"Sample RSS feed: {len(rss_results)} items")

                    for item_idx, item_result in enumerate(rss_results, 1):
                        output_result(item_result)

                        # Save each RSS item as separate JSON artifact
                        if item_result.get('success', False) and item_result.get('data'):
                            try:
                                from .tools.store_emit import store_emit, StoreInput
                                import time

                                # Generate unique filename for RSS item
                                timestamp = int(time.time())
                                output_dir = os.getenv("OUTPUT_DIR", "./out")
                                rss_filename = f"cti_{timestamp}_{item_idx}.json"
                                rss_path = os.path.join(output_dir, rss_filename)

                                store_input = StoreInput(json=item_result['data'], path=rss_path, s3=None)
                                store_result = store_emit(store_input)

                                if store_result.written:
                                    if store_result.locator.startswith("file://"):
                                        file_path = store_result.locator[7:]
                                        item_title = item_result.get('item_metadata', {}).get('title', 'RSS Item')[:50]
                                        print(f"📁 Sample RSS Item: {item_title}... -> {file_path}")
                                else:
                                    logger.warning(f"Failed to save sample RSS item: {item_result.get('url')}")
                            except Exception as save_error:
                                logger.error(f"Error saving sample RSS item: {save_error}")

                else:
                    # Single URL result
                    output_result(result)

                    # Save JSON artifact if processing was successful
                    if result.get('success', False) and result.get('data'):
                        try:
                            from .tools.store_emit import store_emit, StoreInput
                            store_input = StoreInput(json=result['data'], path=None, s3=None)
                            store_result = store_emit(store_input)

                            if store_result.written:
                                if store_result.locator.startswith("file://"):
                                    file_path = store_result.locator[7:]
                                    print(f"📁 CTI JSON saved to: {file_path}")
                            else:
                                logger.warning(f"Failed to save CTI artifact for {test_url}")
                        except Exception as save_error:
                            logger.error(f"Error saving CTI artifact for {test_url}: {save_error}")

            except Exception as e:
                logger.warning(f"Test URL failed: {test_url} - {e}")

    else:
        logger.error("Please provide one of the following:")
        logger.error("  --url https://example.com/feed                (process URL for CTI extraction)")
        logger.error("  --sample-data                                  (test with sample URLs)")
        logger.error("")
        logger.error("Examples:")
        logger.error("  python -m app.cli test --url https://example.com/report")
        logger.error("  python -m app.cli test --url https://example.com/advisory")
        logger.error("  python -m app.cli test --sample-data")
        sys.exit(1)


if __name__ == '__main__':
    cli()