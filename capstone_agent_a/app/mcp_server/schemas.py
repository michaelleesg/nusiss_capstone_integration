"""MCP tool schemas and registration."""

import importlib
import inspect
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def get_all_tools() -> List[Dict[str, Any]]:
    """Get all registered tools with their schemas."""
    tools = []

    # Define tool modules and their tool functions
    tool_modules = [
        ("app.tools.http_fetch", "http_fetch", "HTTP fetch tool"),
        ("app.tools.detect_kind", "detect_kind", "Content type detection"),
        ("app.tools.parsers.misp_parse", "misp_parse_event", "MISP event parser"),
        ("app.tools.parsers.stix_parse", "stix_parse_bundle", "STIX bundle parser"),
        ("app.tools.parsers.rss_parse", "rss_parse", "RSS feed parser"),
        ("app.tools.parsers.html_to_markdown", "html_to_markdown", "HTML to markdown converter"),
        ("app.tools.parsers.pdf_to_text", "pdf_to_text", "PDF to text extractor"),
        ("app.tools.parsers.json_normalize", "json_normalize", "JSON normalizer"),
        ("app.tools.pdf_extract", "extract_pdf_text_and_markup", "PDF text extraction and markup conversion"),
        ("app.tools.nlp", "summarize_threat", "Threat summarization"),
        ("app.tools.nlp", "extract_entities", "Entity extraction"),
        ("app.tools.nlp", "classify_geo_scope", "Geographic scope classifier"),
        ("app.tools.nlp", "classify_high_tension", "High tension event classifier"),
        ("app.tools.nlp", "classify_motivation", "Motivation classifier"),
        ("app.tools.nlp", "is_cyber_related", "Cyber-relatedness classifier"),
        ("app.tools.ioc", "extract_and_normalize", "IOC extraction and normalization"),
        ("app.tools.cve", "extract_from_text", "CVE extraction"),
        ("app.tools.cve", "enrich", "CVE enrichment"),
        ("app.tools.ip_classifier", "classify_ip_addresses", "Batch IP address classification"),
        ("app.tools.schema_validate", "validate_and_heal", "Schema validation and healing"),
        ("app.tools.store_emit", "store_emit", "Storage and emission"),
    ]

    for module_name, func_name, description in tool_modules:
        try:
            module = importlib.import_module(module_name)
            func = getattr(module, func_name)

            # Get input/output types from function signature
            sig = inspect.signature(func)
            input_type = None
            output_type = None

            # Get parameter type annotation
            for param_name, param in sig.parameters.items():
                if param.annotation != inspect.Parameter.empty:
                    input_type = param.annotation
                    break

            # Get return type annotation
            if sig.return_annotation != inspect.Parameter.empty:
                output_type = sig.return_annotation

            if input_type and output_type:
                # Generate tool name from function name
                tool_name = func_name

                tools.append({
                    "name": tool_name,
                    "description": description,
                    "input_schema": input_type.model_json_schema(),
                    "output_schema": output_type.model_json_schema(),
                    "module": module_name,
                    "function": func_name
                })

        except Exception as e:
            logger.warning(f"Failed to register tool {module_name}.{func_name}: {e}")

    logger.info(f"Registered {len(tools)} tools")
    return tools


def get_tool_by_name(name: str) -> Dict[str, Any]:
    """Get tool configuration by name."""
    tools = get_all_tools()
    for tool in tools:
        if tool["name"] == name:
            return tool
    raise ValueError(f"Tool not found: {name}")


def call_tool(name: str, arguments: Dict[str, Any]) -> Any:
    """Call a tool with given arguments."""
    try:
        logger.debug(f"Starting tool call: {name} with args: {arguments}")
        tool_config = get_tool_by_name(name)

        # Import and call the function
        module = importlib.import_module(tool_config["module"])
        func = getattr(module, tool_config["function"])

        # Get input type and validate
        sig = inspect.signature(func)
        input_type = None
        for param_name, param in sig.parameters.items():
            if param.annotation != inspect.Parameter.empty:
                input_type = param.annotation
                break

        if input_type:
            logger.debug(f"Creating input object of type {input_type}")
            # Validate and create input object
            input_obj = input_type(**arguments)
            logger.debug(f"Calling function {func} with input object")
            result = func(input_obj)
        else:
            logger.debug(f"Calling function {func} with raw arguments")
            result = func(**arguments)

        logger.debug(f"Function returned: {type(result)}")

        # Convert result to dict if it's a Pydantic model
        if hasattr(result, "model_dump"):
            logger.debug("Converting result using model_dump()")
            return result.model_dump()
        elif hasattr(result, "dict"):
            logger.debug("Converting result using dict()")
            return result.dict()
        else:
            logger.debug("Returning result as-is")
            return result

    except Exception as e:
        logger.error(f"Error in call_tool for {name}: {e}")
        logger.error(f"Exception type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise