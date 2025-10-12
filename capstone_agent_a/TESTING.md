# Testing Guide

This guide explains how to run tests for the CTI pipeline, including proper MCP server management.

## Quick Start

```bash
# Run all tests with automatic MCP server management
make test-all

# Run only unit tests (no MCP required)
make test-unit

# Run only MCP-dependent tests
make test-mcp
```

## Test Categories

### 1. Unit Tests (No MCP Required)
These test individual agents and components without external dependencies:

```bash
# Run all agent tests
make test-agents

# Run specific agent tests
./cti_env/bin/python -m pytest tests/test_mitre_agent.py -v
./cti_env/bin/python -m pytest tests/test_entity_agent.py -v
```

### 2. Integration Tests (MCP Required)
These test the complete pipeline with MCP tools:

```bash
# Run integration tests with automatic MCP management
make test-integration

# Run specific integration test
./cti_env/bin/python -m pytest tests/test_cti_pipeline.py -v
```

## MCP Server Management

### Method 1: Automatic Management (Recommended)
Use fixtures that automatically start/stop MCP server:

```bash
# Uses fixtures in conftest.py - handles everything automatically
python run_tests_with_mcp.py fixtures -v

# Or use make target
make test-all
```

### Method 2: Manual MCP Server Management
Start MCP server manually, then run tests:

```bash
# Terminal 1: Start MCP server
make start-mcp
# OR
./cti_env/bin/python -m app.cli mcp-server --transport tcp --host 127.0.0.1 --port 8765

# Terminal 2: Run tests
./cti_env/bin/python -m pytest tests/ -v

# Stop server when done
make stop-mcp
```

### Method 3: External Server Management
Let the script manage the server lifecycle:

```bash
python run_tests_with_mcp.py external tests/test_cti_pipeline.py -v
```

## Test Selection

### Run by Markers
```bash
# Run only MCP-dependent tests
./cti_env/bin/python -m pytest -m mcp -v

# Run tests excluding MCP dependencies
./cti_env/bin/python -m pytest -m "not mcp" -v

# Run integration tests
./cti_env/bin/python -m pytest -m integration -v
```

### Run by File Pattern
```bash
# Run all agent tests
./cti_env/bin/python -m pytest tests/test_*_agent.py -v

# Run specific test files
./cti_env/bin/python -m pytest tests/test_fetch_agent.py tests/test_ioc_agent.py -v
```

### Run Specific Tests
```bash
# Run specific test method
./cti_env/bin/python -m pytest tests/test_mitre_agent.py::TestMitreAgent::test_agent_initialization -v

# Run specific test class
./cti_env/bin/python -m pytest tests/test_entity_agent.py::TestEntityAgent -v
```

## Test Configuration

### Environment Variables
Set these before running tests:

```bash
export OPENAI_API_KEY="your-key-here"
export DATABASE_URL="sqlite:///test.db"  # Optional - uses temp DB by default
export LOG_LEVEL="INFO"  # Optional
```

### Pytest Configuration
Configuration is in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"
markers = [
    "mcp: marks tests as requiring MCP server",
    "integration: marks tests as integration tests",
    "slow: marks tests as slow running",
]
```

## Test Structure

```
tests/
├── conftest.py              # Fixtures and test configuration
├── agent_tester.py          # Individual agent testing framework
├── test_*_agent.py          # Individual agent tests (unit tests)
├── test_parse_agents.py     # Parser agent tests
├── test_integration.py      # End-to-end pipeline tests
├── test_cti_pipeline.py     # MCP pipeline tests
└── __init__.py             # Test package initialization
```

All test files are now consolidated in the `/tests` directory for better organization and easier discovery.

## Fixtures Available

### Core Fixtures
- `sample_url`: Test URL
- `sample_html_content`: Realistic HTML with ads/navigation
- `sample_stix_content`: Complete STIX bundle with threat actors
- `sample_extracted_data`: Sample CTI extraction results
- `mock_graph_state`: Pre-configured GraphState for testing

### MCP Fixtures
- `mcp_server`: Session-scoped MCP server (automatic start/stop)
- `mcp_client`: MCP client connected to test server
- `setup_mcp_for_integration_tests`: Conditional MCP setup

### Database Fixtures
- `test_database_url`: Temporary SQLite database
- `test_memory_system`: Fresh memory system per test

## Debugging Tests

### Verbose Output
```bash
./cti_env/bin/python -m pytest tests/ -v -s --tb=long
```

### Run Specific Failing Test
```bash
./cti_env/bin/python -m pytest tests/test_mitre_agent.py::TestMitreAgent::test_successful_mitre_mapping -v -s
```

### Check MCP Server Status
```bash
# Test MCP server connectivity
./cti_env/bin/python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('127.0.0.1', 8765))
print('MCP server is', 'running' if result == 0 else 'not running')
sock.close()
"
```

### View Test Coverage
```bash
make test-coverage
# Open htmlcov/index.html in browser
```

## Common Issues

### Issue: "MCP server not started"
**Solution**: Use automatic fixtures or start server manually:
```bash
make start-mcp  # In separate terminal
```

### Issue: "No module named 'app'"
**Solution**: Ensure you're in the project root and using the virtual environment:
```bash
cd /path/to/capstone_agentic_cti
source cti_env/bin/activate  # or use ./cti_env/bin/python
```

### Issue: "Port already in use"
**Solution**: Stop existing MCP server or use different port:
```bash
make stop-mcp
# Or find and kill process:
lsof -ti:8765 | xargs kill
```

### Issue: GraphState validation errors
**Solution**: Ensure GraphState has required URL field:
```python
# Wrong
state = GraphState()

# Correct
state = GraphState(url="https://test.com")
```

## Performance

### Fast Tests (Unit only)
```bash
make test-unit  # ~30 seconds
```

### Full Test Suite
```bash
make test-all   # ~5-10 minutes with MCP startup
```

### Smoke Test
```bash
make smoke-test  # ~10 seconds - just initialization tests
```

## CI/CD Integration

For automated testing environments:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    make install
    make test-no-mcp  # Skip MCP for faster CI

# For full integration testing
- name: Run integration tests
  run: |
    make test-all
```

## Contributing

When adding new tests:

1. **Unit tests**: Add to appropriate `test_*_agent.py` file
2. **Integration tests**: Add to `test_integration.py`
3. **MCP-dependent tests**: Mark with `@pytest.mark.mcp`
4. **Use fixtures**: Leverage existing fixtures in `conftest.py`
5. **Follow naming**: Use `test_*` naming convention

Example new test:
```python
@pytest.mark.mcp
def test_new_mcp_feature(mcp_client, sample_state):
    """Test new MCP-dependent feature."""
    result = mcp_client.call_tool("new_tool", {"input": "test"})
    assert result["status"] == "success"
```