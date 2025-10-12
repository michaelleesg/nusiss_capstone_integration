# Docker Architecture Guide

## How CTI App Connects to MCP Server

### Architecture Overview

```
┌─────────────────┐         TCP          ┌──────────────────┐
│  cti-processor  │ ───────────────────→ │ mcp-server-tcp   │
│  (CTI App)      │  tcp://host:8765     │ (MCP Tools)      │
└─────────────────┘                       └──────────────────┘
```

### Connection Configuration

The CTI app knows how to connect via **environment variables**:

```yaml
environment:
  # MCP Server connection settings
  - MCP_TRANSPORT=tcp           # Use TCP transport (vs stdio)
  - MCP_HOST=mcp-server-tcp     # Docker service name
  - MCP_PORT=8765               # Port number
  - MCP_START_SERVER=false      # Don't start own server, connect to existing
```

These are read by `app/config.py` → `MCPConfig` class.

### Service Dependencies

```yaml
depends_on:
  mcp-server-tcp:
    condition: service_started  # Wait for MCP server to start first
```

Docker Compose ensures:
1. `mcp-server-tcp` starts first
2. `cti-processor` waits until MCP server is running
3. `cti-processor` connects to MCP server via internal Docker network

### Internal Docker Networking

- Services communicate via **service names** as hostnames
- `mcp-server-tcp` is accessible at `tcp://mcp-server-tcp:8765`
- No need for `localhost` or IP addresses
- External access via port mapping: `127.0.0.1:8765 → mcp-server-tcp:8765`

## Usage Examples

### Example 1: Single URL Processing

```bash
# Start both MCP server and processor
TARGET_URL="https://example.com/advisory" \
docker-compose --profile processor --profile mcp-tcp up
```

**What happens**:
1. MCP server starts listening on `0.0.0.0:8765` (inside container)
2. Processor starts and connects to `mcp-server-tcp:8765`
3. Processor calls MCP tools via TCP
4. Output saved to `./out/`

### Example 2: Batch Processing

```bash
# Create URL file
cat > urls.txt <<EOF
https://www.cisa.gov/news
https://www.bleepingcomputer.com/feed
EOF

# Process batch with MCP server
docker-compose --profile batch --profile mcp-tcp up
```

### Example 3: Long-Running MCP Server

```bash
# Start MCP server in background
docker-compose --profile mcp-tcp up -d

# Process multiple URLs using same server
TARGET_URL="https://example1.com" docker-compose --profile processor up
TARGET_URL="https://example2.com" docker-compose --profile processor up
TARGET_URL="https://example3.com" docker-compose --profile processor up

# Stop server when done
docker-compose --profile mcp-tcp down
```

### Example 4: External MCP Client

If you want to connect from outside Docker:

```bash
# Start MCP server (exposes port 8765)
docker-compose --profile mcp-tcp up -d

# Connect from host machine
python your_client.py --mcp-host localhost --mcp-port 8765
```

## Configuration Override

### Use Different MCP Server

```yaml
cti-processor:
  environment:
    - MCP_HOST=external-mcp-server.example.com
    - MCP_PORT=9000
```

### Use Embedded MCP Server (No Dependency)

```yaml
cti-processor:
  environment:
    - MCP_TRANSPORT=stdio           # Use stdio instead of TCP
    - MCP_START_SERVER=true         # Start own embedded server
  # Remove depends_on
```

## Troubleshooting

### Issue: "Connection refused" to MCP server

**Check**:
1. Is MCP server running? `docker ps | grep mcp-server-tcp`
2. Are both services in same profile? Need both `--profile processor --profile mcp-tcp`
3. Check logs: `docker-compose logs mcp-server-tcp`

**Solution**:
```bash
# Ensure both profiles are active
docker-compose --profile processor --profile mcp-tcp up
```

### Issue: "MCP_HOST not found"

**Cause**: Services not on same Docker network

**Solution**: Services in same compose file automatically share a network. If using separate files:

```yaml
networks:
  cti-network:
    external: true

services:
  cti-processor:
    networks:
      - cti-network
  mcp-server-tcp:
    networks:
      - cti-network
```

### Issue: MCP server starts but processor can't connect

**Debug**:
```bash
# Check if MCP server is listening
docker exec -it mcp-server-tcp netstat -tlnp | grep 8765

# Test connection from processor
docker exec -it cti-processor nc -zv mcp-server-tcp 8765

# Check environment variables
docker exec -it cti-processor env | grep MCP
```

## Performance Considerations

### Shared MCP Server Benefits

✅ **Advantages**:
- Single server handles multiple requests
- Reduced memory footprint
- Faster processing (no server startup delay)
- Better for batch processing

### Embedded MCP Server (stdio)

✅ **Advantages**:
- No network overhead
- Simpler deployment
- Process isolation

❌ **Disadvantages**:
- Each processor starts own server (slower)
- Higher memory usage for multiple processors
- Can't share server across containers

## Production Deployment

### Recommended Architecture

```yaml
services:
  # Dedicated MCP server (always running)
  mcp-server:
    deploy:
      replicas: 2  # For redundancy
      resources:
        limits:
          cpus: '2'
          memory: 4G
    restart: always
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "8765"]
      interval: 10s
      timeout: 5s
      retries: 3

  # Processor workers (scale as needed)
  cti-worker:
    deploy:
      replicas: 5
    depends_on:
      mcp-server:
        condition: service_healthy
```

### Load Balancing

For multiple MCP servers:

```yaml
services:
  mcp-server-1:
    ports:
      - "8765:8765"

  mcp-server-2:
    ports:
      - "8766:8765"

  # Use HAProxy/nginx to load balance
  load-balancer:
    image: haproxy
    ports:
      - "8765:8765"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
```

## Summary

**Key Points**:

1. **Environment Variables** tell CTI app how to connect:
   - `MCP_TRANSPORT=tcp`
   - `MCP_HOST=mcp-server-tcp` (Docker service name)
   - `MCP_PORT=8765`
   - `MCP_START_SERVER=false`

2. **Service Dependencies** ensure correct startup order:
   - `depends_on: mcp-server-tcp`

3. **Docker Networking** allows services to communicate by name:
   - `tcp://mcp-server-tcp:8765` (internal)
   - `tcp://localhost:8765` (external via port mapping)

4. **Profiles** control which services start:
   - `--profile processor --profile mcp-tcp`
