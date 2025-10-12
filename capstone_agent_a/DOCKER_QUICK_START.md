# Docker Quick Start

## Prerequisites

```bash
# 1. Set up environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# 2. Build image
docker-compose build
```

## Common Commands

### Process Single URL

```bash
TARGET_URL="https://www.cisa.gov/news-events/advisories" \
docker-compose --profile processor --profile mcp-tcp up
```

### Process Batch URLs

```bash
# Create URL file
cat > urls.txt <<EOF
https://www.cisa.gov/news
https://thehackernews.com/
EOF

# Run batch processing
docker-compose --profile batch --profile mcp-tcp up
```

### Run MCP Server Only

```bash
# Start in background
docker-compose --profile mcp-tcp up -d

# Check logs
docker-compose logs -f mcp-server-tcp

# Stop
docker-compose --profile mcp-tcp down
```

### Clean Up

```bash
# Stop all services
docker-compose --profile processor --profile mcp-tcp down

# Remove volumes (WARNING: deletes database)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## Quick Reference

| Task | Command |
|------|---------|
| Build image | `docker-compose build` |
| Process URL | `TARGET_URL="..." docker-compose --profile processor --profile mcp-tcp up` |
| Batch process | `docker-compose --profile batch --profile mcp-tcp up` |
| Start MCP server | `docker-compose --profile mcp-tcp up -d` |
| View logs | `docker-compose logs -f [service-name]` |
| Stop services | `docker-compose --profile [profile] down` |
| Reset database | `docker-compose run --rm cti-processor python -m app.cli db --reset` |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | - | **Required** OpenAI API key |
| `LLM_MODEL` | `gpt-4o-mini` | LLM model to use |
| `TARGET_URL` | - | URL to process (processor profile) |
| `MCP_TRANSPORT` | `tcp` | Transport type (tcp/stdio) |
| `MCP_HOST` | `mcp-server-tcp` | MCP server hostname |
| `MCP_PORT` | `8765` | MCP server port |
| `MCP_START_SERVER` | `false` | Start embedded server |

## Profiles

| Profile | Services Started | Use Case |
|---------|-----------------|----------|
| `processor` + `mcp-tcp` | cti-processor, mcp-server-tcp | Single URL processing |
| `batch` + `mcp-tcp` | cti-batch, mcp-server-tcp | Batch URL processing |
| `mcp-tcp` | mcp-server-tcp | Run MCP server standalone |
| `mcp-stdio` | mcp-server-stdio | MCP server with stdio |

## Outputs

- **JSON artifacts**: `./out/cti_*.json`
- **Database**: `./data/cti.db`
- **Logs**: Use `docker-compose logs`

## Examples

### Process CISA Advisory

```bash
TARGET_URL="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-215a" \
docker-compose --profile processor --profile mcp-tcp up
```

### Process RSS Feed

```bash
TARGET_URL="https://feeds.feedburner.com/eset/blog" \
docker-compose --profile processor --profile mcp-tcp up
```

### Test with Sample Data

```bash
docker-compose run --rm cti-processor python -m app.cli test --sample-data
```

## Troubleshooting

### "Connection refused" error

**Issue**: Processor can't connect to MCP server

**Fix**: Ensure both profiles are active:
```bash
docker-compose --profile processor --profile mcp-tcp up
```

### "OPENAI_API_KEY not set"

**Issue**: Missing API key

**Fix**:
```bash
echo "OPENAI_API_KEY=sk-your-key-here" > .env
```

### Container exits immediately

**Issue**: Wrong profile or missing URL

**Fix**: Check you're using correct profile and providing URL
```bash
TARGET_URL="https://example.com" \
docker-compose --profile processor --profile mcp-tcp up
```

### Out of memory

**Issue**: Docker memory limit too low

**Fix**: Increase Docker Desktop memory to 4GB+ in settings

## Architecture

```
┌─────────────────┐
│  cti-processor  │  ← Your URL
└────────┬────────┘
         │ tcp://mcp-server-tcp:8765
         ↓
┌─────────────────┐
│ mcp-server-tcp  │  ← MCP Tools (parsers, extractors, etc.)
└────────┬────────┘
         ↓
    ./out/cti_*.json  ← Output
```

## Next Steps

- Read [DOCKER_ARCHITECTURE.md](DOCKER_ARCHITECTURE.md) for detailed architecture
- Read [DOCKER_USAGE.md](DOCKER_USAGE.md) for advanced usage
- Check [README.md](README.md) for general project info
