.PHONY: install dev run run-sse test lint clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

run:
	@echo "Starting VIGIL MCP (stdio)..."
	cd src && python3 -m vigil_mcp.server

run-sse:
	@echo "Starting VIGIL MCP (SSE on :3100)..."
	cd src && VIGIL_MCP_TRANSPORT=sse VIGIL_MCP_PORT=3100 python3 -m vigil_mcp.server

test:
	python3 -m pytest tests/ -v

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

help:
	@echo "VIGIL MCP Server"
	@echo ""
	@echo "  make install    Install package"
	@echo "  make dev        Install with dev dependencies"
	@echo "  make run        Run MCP server (stdio)"
	@echo "  make run-sse    Run MCP server (SSE on :3100)"
	@echo "  make test       Run tests"
	@echo "  make lint       Check code style"
	@echo "  make format     Auto-format code"
	@echo "  make clean      Remove build artifacts"
