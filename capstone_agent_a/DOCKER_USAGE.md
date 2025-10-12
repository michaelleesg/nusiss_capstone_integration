# Docker Usage Guide

This guide explains how to run the CTI application using Docker Compose.

## Prerequisites

1. **Docker and Docker Compose** installed
2. **OpenAI API Key** (required for LLM processing)

## Quick Start

### 1. Configure Environment Variables

Copy the example environment file and add your API key:

```bash
cp .env.example .env
```

Edit `.env` and set your `OPENAI_API_KEY`:

```bash
OPENAI_API_KEY=***REMOVED***
```

### 2. Build the Docker Image

```bash
docker-compose build
```

## Usage Scenarios

### Scenario 1: Process a Single URL

Pass the URL via environment variable:

```bash
TARGET_URL="https://www.cisa.gov/news-events/cybersecurity-advisories" \
docker-compose --profile processor up
```

**Output**: JSON artifacts saved to `./out/` directory

### Scenario 2: Process Multiple URLs from a File

Create a file `urls.txt` with one URL per line:

```bash
cat > urls.txt <<EOF
https://www.cisa.gov/news-events/cybersecurity-advisories
https://www.bleepingcomputer.com/news/security/
https://thehackernews.com/
EOF
```

Run batch processing:

```bash
docker-compose --profile batch up
```

### Scenario 3: Run MCP Server (STDIO Transport)

For integration with MCP clients using standard input/output:

```bash
docker-compose --profile mcp-stdio up
```

This runs the MCP server in stdio mode for JSON-RPC communication.

### Scenario 4: Run MCP Server (TCP Transport)

For network-accessible MCP server:

```bash
docker-compose --profile mcp-tcp up -d
```

The MCP server will be available at `tcp://localhost:8765`

To stop:

```bash
docker-compose --profile mcp-tcp down
```

### Scenario 5: Interactive Testing

Run the container interactively to test with different URLs:

```bash
docker-compose run --rm cti-app python -m app.cli test \
  --url "https://www.cisa.gov/news-events/alerts"
```

### Scenario 6: Database Management

Reset the database:

```bash
docker-compose run --rm cti-app python -m app.cli db --reset
```

Check database stats:

```bash
docker-compose run --rm cti-app python -m app.cli db
```

## Advanced Usage

### Custom Command Execution

Run any CLI command in the container:

```bash
docker-compose run --rm cti-app python -m app.cli [command] [options]
```

Examples:

```bash
# Run with custom options
docker-compose run --rm cti-app python -m app.cli run \
  "https://example.com/advisory" \
  --output-dir /app/out \
  --no-ssl-verify

# Validate a CTI artifact
docker-compose run --rm cti-app python -m app.cli validate \
  /app/out/cti_1234567890.json --pretty

# MCP demo
docker-compose run --rm cti-app python -m app.cli mcp-demo
```

### Environment Variable Override

Override any environment variable at runtime:

```bash
LLM_MODEL=gpt-4 TARGET_URL="https://example.com" \
docker-compose --profile processor up
```

### Volume Mounts

The setup includes persistent volumes:

- `./out` - Output artifacts (JSON files)
- `./data` - Database files (SQLite)
- `./.env` - Environment configuration (read-only)

### Authentication and SSL

For URLs requiring authentication:

```bash
docker-compose run --rm cti-app python -m app.cli run \
  "https://protected.example.com/feed" \
  --auth-username user \
  --auth-password pass
```

For URLs with SSL issues:

```bash
docker-compose run --rm cti-app python -m app.cli run \
  "https://self-signed.example.com" \
  --no-ssl-verify
```

## Monitoring and Logs

View logs in real-time:

```bash
docker-compose --profile processor logs -f
```

View MCP server logs:

```bash
docker-compose --profile mcp-tcp logs -f mcp-server-tcp
```

## Cleanup

Remove containers and volumes:

```bash
# Remove all containers
docker-compose --profile processor down
docker-compose --profile mcp-tcp down

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## Troubleshooting

### Issue: "OPENAI_API_KEY not set"

**Solution**: Ensure `.env` file exists and contains valid API key:

```bash
echo "OPENAI_API_KEY=sk-your-key" > .env
```

### Issue: Permission denied on output directory

**Solution**: Ensure output directory is writable:

```bash
mkdir -p out data
chmod 777 out data
```

### Issue: Out of memory during build

**Solution**: Increase Docker memory limit in Docker Desktop settings or use slim dependencies.

### Issue: Container exits immediately

**Solution**: Check if you're using the correct profile:

```bash
docker-compose --profile processor up
```

## Production Deployment

For production deployments:

1. **Use secrets management** instead of `.env` files
2. **Configure S3 storage** for artifact persistence:
   ```bash
   S3_BUCKET=my-cti-artifacts
   AWS_ACCESS_KEY_ID=your-key
   AWS_SECRET_ACCESS_KEY=your-secret
   ```
3. **Use external database** instead of SQLite:
   ```bash
   DATABASE_URL=postgresql://user:pass@host:5432/cti
   ```
4. **Enable SSL/TLS** for MCP TCP transport
5. **Set up monitoring** with health checks

## Performance Tuning

### Concurrent Processing

For batch processing with concurrency:

```bash
docker-compose run --rm -e CONCURRENT_REQUESTS=5 cti-batch
```

### Resource Limits

Add resource limits to docker-compose.yml:

```yaml
services:
  cti-processor:
    # ... existing config ...
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

## Examples

### Process a CISA Advisory

```bash
TARGET_URL="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-215a" \
docker-compose --profile processor up
```

### Process RSS Feed

```bash
TARGET_URL="https://feeds.feedburner.com/eset/blog" \
docker-compose --profile processor up
```

### Test Pipeline with Sample Data

```bash
docker-compose run --rm cti-app python -m app.cli test --sample-data
```

## Integration with CI/CD

Example GitHub Actions workflow:

```yaml
- name: Process CTI URLs
  run: |
    docker-compose --profile batch up
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Support

For issues or questions:
1. Check logs: `docker-compose logs`
2. Review configuration: `.env` file
3. Test connectivity: `docker-compose run --rm cti-app curl -I https://example.com`
