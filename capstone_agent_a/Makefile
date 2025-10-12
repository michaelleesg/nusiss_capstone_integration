# CTI Pipeline Testing Makefile

.PHONY: test test-all test-mcp test-no-mcp test-unit test-integration start-mcp stop-mcp

# Default Python and pytest commands
PYTHON = ./cti_env/bin/python
PYTEST = $(PYTHON) -m pytest

# Test targets
test: test-unit
	@echo "✅ Unit tests completed"

test-all:
	@echo "🚀 Running all tests with automatic MCP server management..."
	$(PYTHON) run_tests_with_mcp.py fixtures -- tests -v

test-mcp:
	@echo "🔧 Running only MCP-dependent tests..."
	$(PYTHON) run_tests_with_mcp.py mcp-only -- tests -v

test-no-mcp:
	@echo "⚡ Running tests without MCP dependencies..."
	$(PYTHON) run_tests_with_mcp.py no-mcp -- tests -v

test-unit:
	@echo "🧪 Running unit tests (agent tests without MCP)..."
	$(PYTEST) tests/test_*_agent.py -v --tb=short

test-integration:
	@echo "🔗 Running integration tests with MCP server..."
	$(PYTHON) run_tests_with_mcp.py fixtures -- tests/test_integration.py tests/test_cti_pipeline.py -v

test-agents:
	@echo "🤖 Running all agent tests..."
	$(PYTEST) tests/test_*_agent.py tests/test_parse_agents.py -v --tb=short

test-framework:
	@echo "🧪 Testing the agent testing framework..."
	$(PYTHON) -c "from tests.agent_tester import AgentTester; print('✅ Agent testing framework works')"

test-specific:
	@echo "🎯 Running specific test file: $(FILE)"
	$(PYTEST) $(FILE) -v

# MCP server management
start-mcp:
	@echo "🚀 Starting MCP server..."
	$(PYTHON) -m app.cli mcp-server --transport tcp --host 127.0.0.1 --port 8765 &
	@echo "MCP server started on tcp://127.0.0.1:8765"

stop-mcp:
	@echo "🛑 Stopping MCP server..."
	@pkill -f "app.cli mcp-server" || echo "No MCP server found"

# Coverage testing
test-coverage:
	@echo "📊 Running tests with coverage..."
	$(PYTEST) --cov=app --cov-report=html --cov-report=term -v

# Quick smoke test
smoke-test:
	@echo "💨 Running smoke tests..."
	$(PYTEST) tests/ -k "test_agent_initialization" -v

# Development helpers
lint:
	@echo "🔍 Running linting..."
	$(PYTHON) -m ruff check app/ tests/
	$(PYTHON) -m black --check app/ tests/

format:
	@echo "✨ Formatting code..."
	$(PYTHON) -m black app/ tests/
	$(PYTHON) -m ruff check --fix app/ tests/

install:
	@echo "📦 Installing dependencies..."
	./cti_env/bin/pip install -e ".[dev]"

# Help
help:
	@echo "CTI Pipeline Testing Commands:"
	@echo ""
	@echo "Test Commands:"
	@echo "  make test          - Run unit tests (default)"
	@echo "  make test-all      - Run all tests with automatic MCP management"
	@echo "  make test-mcp      - Run only MCP-dependent tests"
	@echo "  make test-no-mcp   - Run tests without MCP dependencies"
	@echo "  make test-unit     - Run unit tests only"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-agents   - Run all agent tests"
	@echo "  make smoke-test    - Quick smoke test"
	@echo "  make test-coverage - Run tests with coverage"
	@echo ""
	@echo "MCP Management:"
	@echo "  make start-mcp     - Start MCP server manually"
	@echo "  make stop-mcp      - Stop MCP server"
	@echo ""
	@echo "Development:"
	@echo "  make lint          - Run code linting"
	@echo "  make format        - Format code"
	@echo "  make install       - Install dependencies"
	@echo ""
	@echo "Examples:"
	@echo "  make test-specific FILE=tests/test_mitre_agent.py"
	@echo "  make test-all"
	@echo "  make test-mcp"