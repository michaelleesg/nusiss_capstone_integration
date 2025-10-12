# Agentic CTI URL→JSON Pipeline

An advanced **Cyber Threat Intelligence (CTI) processing pipeline** that transforms URLs into structured JSON artifacts using **LangGraph + MCP (Model Context Protocol)** architecture with persistent memory and deduplication.

## 🚀 Overview

This system ingests threat intelligence from various sources (MISP events, STIX bundles, RSS feeds, HTML pages, PDFs, JSON documents) and produces normalized, enriched CTI artifacts with:

- **Automated content type detection** and parsing
- **Entity extraction** (threat actors, malware, victims, sectors)
- **IOC normalization** (URLs, domains, IPs, file hashes)
- **CVE enrichment** with CISA KEV integration
- **MITRE ATT&CK technique mapping**
- **Geographic scope analysis** (Singapore/ASEAN focus)
- **Deduplication** via SHA-256 content hashing
- **Persistent memory** for idempotent processing

## 📋 Features

### Core Pipeline
- **Multi-format parsing**: MISP, STIX 2.x, RSS/Atom, HTML, PDF, JSON, plain text
- **Content type detection**: Intelligent routing based on MIME types and content analysis
- **Threat intelligence extraction**: Automated identification of cyber threats, actors, and TTPs

### Intelligence Enrichment
- **IOC extraction & normalization**: URLs, domains, IPs, file hashes with canonicalization
- **CVE analysis**: Extraction, severity assessment, patch availability, active exploitation status
- **MITRE ATT&CK mapping**: Technique identification from content and known actor/malware profiles
- **Entity recognition**: Threat actors, malware families, affected products, victim organizations
- **Geographic impact assessment**: Singapore and ASEAN region focus

### Memory & Deduplication
- **SQLite-based persistence**: Content tracking with SHA-256 hashing
- **Automatic deduplication**: Skip processing of previously analyzed content
- **Canonical URL handling**: Normalization and tracking of content sources
- **Index management**: IOC and CVE databases for cross-reference

### MCP Server Architecture
- **Tool exposure**: All processing tools available via JSON-RPC over stdio
- **Standardized I/O**: Pydantic models for robust input/output validation
- **Agent integration**: Compatible with MCP-enabled AI agents and tools

## 🛠️ Installation

### Prerequisites
- Python 3.12+
- OpenAI API key for LLM
- NVD API key

### Recommended: Docker container
1. **Build containers**
docker compose --profile processor --profile mcp-tcp build

2. **Start containers**
```bash
TARGET_URL="https://www.inoreader.com/stream/user/1005039686/tag/Grade%20A" docker-compose --profile processor --profile mcp-tcp up --abort-on-container-exit
```
- **Example**: The example given above is a RSS feed with 20 items.
- **Note**: Processed URLs will be remembered in a SQLite folder (./data/cti.db). If you run the same URL again, will skip processing. Delete ./data/cti.db to reset
- **CRON**: Ideally, run this every 15min or so


3. **Get output**
See ./out/ folder for JSON files


### Setup

1. **Clone and install:**
```bash
git clone <repository-url>
cd <repository>
pip install -e .
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your OpenAI API key and other settings
```

3. **Initialize database:**
```bash
python -m app.cli db --reset
```

4. **Run tests:**
```bash
pip install -e ".[dev]"
pytest
```

## 🚀 Usage

### Command Line Interface

**Process single URL:**
```bash
python -m app.cli run https://example.com/threat-report
```

### MCP Server

**Start MCP server:**
```bash
python -m app.cli mcp-server
```

**Test MCP client:**
```bash
python -m app.cli mcp-demo
```

### Output Format

Each processed URL produces a JSON artifact with the complete CTI schema:

```json
{
  "title": "Critical RCE Vulnerability in Popular Software",
  "url": "https://example.com/advisory",
  "summary": "CVE-2023-12345 allows remote code execution...",
  "threat_actors": ["APT29", "Lazarus Group"],
  "malware": ["CozyLoader", "BLINDINGCAN"],
  "cve_vulns": ["CVE-2023-12345"],
  "affected_products": ["Windows Server 2019", "Adobe Reader"],
  "iocs": {
    "urls": ["https://evil-domain.org/payload.exe"],
    "domains": ["malicious-example.com"],
    "hashes": ["abc123def456..."],
    "ips": ["203.45.67.89"]
  },
  "mitre_ttps": ["T1566.001", "T1059.001", "T1112"],
  "victims": ["Government Agency"],
  "sectors": ["Government", "Energy"],
  "patch_availability": true,
  "affects_singapore": true,
  "affects_asean": true,
  "active_exploitation": true,
  "high_tension_event": true,
  "possible_motivations": ["espionage"],
  "recommendations_and_mitigations": ["Apply patches immediately"],
  "cve_severity": {"CVE-2023-12345": "CRITICAL"},
  "sanitised_html_markdown": "# Advisory\n\nCritical vulnerability...",
  "cyber_related": true
}
```

## 🏗️ Architecture

### Hybrid Agentic-Parallel Workflow

The system uses an intelligent hybrid approach that combines:
- **Agentic AI decision-making** for optimal processing paths
- **Parallel execution** when tasks are independent for maximum performance
- **Adaptive strategy** that adjusts based on content type and complexity

```
Fetch → DetectType → AI Decision → Route{ParseMISP|ParseSTIX|ParseRSS|ParseHTML|ParsePDF|ParseJSON|ParseTEXT}
      → AI Decision → Summarize → AI Decision → [Entities | IOCs | CVEs | MITRE] (parallel when optimal)
      → [Geo/Motivation | Cyberness] (parallel when optimal) → ValidateFill → Store
```

The AI orchestrator intelligently decides:
- When to run tasks sequentially (dependencies exist)
- When to parallelize (independent tasks for performance)
- What processing steps are needed based on content

### MCP Tools Available

| Tool | Description | Input | Output |
|------|-------------|-------|---------|
| `http.fetch_url` | Fetch and analyze URL content | `{url, timeout_s, max_bytes}` | `{status, headers, mime, content_b64, sha256}` |
| `detect.kind` | Detect content type | `{mime, sample_text}` | `{detected_type, confidence}` |
| `misp.parse_event` | Parse MISP event JSON | `{json}` | `{event, attributes, tags}` |
| `stix.parse_bundle` | Parse STIX 2.x bundle | `{json}` | `{objects, relationships, report}` |
| `rss.parse` | Parse RSS/Atom feeds | `{xml}` | `{items, feed}` |
| `html.to_markdown` | Convert HTML to markdown | `{html, url}` | `{markdown, metadata}` |
| `pdf.to_text` | Extract text from PDF | `{pdf_b64}` | `{text}` |
| `nlp.summarize_threat` | Generate threat summary | `{type, title, text}` | `{summary, evidence}` |
| `nlp.extract_entities` | Extract threat entities | `{text, aliases}` | `{threat_actors, malware, victims, sectors, products}` |
| `ioc.extract_and_normalize` | Extract IOCs | `{text}` | `{urls, domains, hashes, ips}` |
| `cve.extract_from_text` | Extract CVE identifiers | `{text}` | `{cves}` |
| `cve.enrich` | Enrich CVE data | `{cves, prefer_offline_cache}` | `{severity, patch_available, active_exploitation}` |
| `mitre.map_ttps` | Map MITRE ATT&CK techniques | `{text, malware, actors}` | `{techniques, evidence}` |
| `schema.validate_and_heal` | Validate and fix JSON schema | `{json, schema}` | `{ok, errors, healed}` |
| `store.emit` | Store artifact | `{json, path, s3}` | `{written, locator}` |

## 🗄️ Data Storage

### SQLite Database Schema

**Contents Table:**
- URL tracking with canonical normalization
- SHA-256 content hashing for deduplication
- Artifact path references for short-circuiting

**IOC Index:**
- Normalized IOC values across all processed content
- Type categorization (url, domain, hash, ip)

**CVE Index:**
- CVE tracking with severity and patch status
- Integration with CISA Known Exploited Vulnerabilities

**Run Index:**
- Processing run metadata and timing

### File Output
- Individual JSON artifacts: `/out/{sha256}.json`
- Optional S3 integration for cloud storage
- Canonical schema validation and healing

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for NLP processing | Required |
| `OPENAI_MODEL` | OpenAI model to use | `gpt-4-turbo-preview` |
| `DATABASE_URL` | SQLite database path | `sqlite:///./data/cti.db` |
| `OUTPUT_DIR` | Output directory for artifacts | `./out` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `MAX_RETRIES` | Network request retries | `3` |
| `TIMEOUT_SECONDS` | Request timeout | `20` |
| `MAX_CONTENT_BYTES` | Maximum content size | `5000000` |

### External Data Sources

- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **MITRE ATT&CK**: Enterprise techniques and procedures
- **NVD**: National Vulnerability Database (future integration)

## 🧪 Testing

### Test Suite
```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_detect_kind.py
pytest tests/test_ioc_normalize.py
pytest tests/test_html_pipeline.py
```

### Test Coverage
- Content type detection across all supported formats
- IOC extraction and normalization with edge cases
- CVE enrichment with mock KEV data
- Schema validation and healing
- Deduplication and memory system functionality
- Full HTML processing pipeline
- Storage and retrieval operations

## 🔒 Security Considerations

### Defensive Focus
- **No malicious tool creation**: Designed for defensive security analysis only
- **IOC defanging**: Automatic handling of defanged indicators
- **Input validation**: Robust Pydantic models prevent injection attacks
- **Content limits**: Size restrictions prevent DoS via large inputs

### Data Privacy
- **Local processing**: Default SQLite storage keeps data on-premises
- **Optional cloud**: S3 integration available but not required
- **Content hashing**: SHA-256 for integrity without exposing content

## 🤝 Contributing

1. **Development setup:**
```bash
pip install -e ".[dev]"
pre-commit install
```

2. **Code quality:**
```bash
ruff check .
black .
mypy .
```

3. **Test contributions:**
```bash
pytest --cov=app tests/
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Common Issues

**OpenAI API Errors:**
- Verify API key in `.env` file
- Check rate limits and billing status

**Database Issues:**
- Reset database: `python -m app.cli db --reset`
- Check file permissions in `./data/` directory

**Memory Issues:**
- Reduce `MAX_CONTENT_BYTES` for large documents
- Use parallel processing carefully with memory constraints

### Getting Help

- **Documentation**: See `/docs` directory for detailed guides
- **Issues**: Report bugs via GitHub Issues
- **Development**: Check `CONTRIBUTING.md` for development guidelines

---

**Built with ❤️ for the cybersecurity community**
