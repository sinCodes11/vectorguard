<div align="center">
  <img src="assets/banner.svg" width="100%"/>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square" alt="python">
  <img src="https://img.shields.io/badge/RAG-pgvector-3b82f6?style=flat-square" alt="RAG">
  <img src="https://img.shields.io/badge/API-FastAPI-009688?style=flat-square" alt="API">
  <img src="https://img.shields.io/badge/focus-defensive-00ff88?style=flat-square" alt="focus">
</p>


<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/RAG-ChromaDB-a855f7?style=flat-square" alt="RAG">
  <img src="https://img.shields.io/badge/FastAPI-backend-00b4d8?style=flat-square" alt="FastAPI">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

Self-hosted threat intelligence knowledge base that ingests CVE databases and security advisories and exposes them via natural language queries. Ask "critical vulnerabilities in Apache last 90 days" and get ranked, contextualized results — not raw JSON.

## Features

- **Real-time Ingestion** — Automated ingestion from NVD, CISA, US-CERT, Microsoft, Apple, Red Hat
- **RAG-Powered Search** — Natural language queries with semantic ranking
- **Vector Embeddings** — Similarity search via sentence-transformers + ChromaDB
- **CVE Database** — CVSS scores, affected versions, analysis
- **REST API** — Full programmatic access with JWT/API key auth
- **Web Interface** — Responsive search UI (Next.js)
- **Self-Hosted** — Complete Docker deployment

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │     API         │    │   Ingestion     │
│   (Next.js)     │◄──►│   (FastAPI)     │◄──►│   (Celery)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                       ┌────────┴────────┐
                       │                 │
                ┌──────▼─────┐    ┌──────▼─────┐
                │ PostgreSQL │    │   Redis    │
                └────────────┘    └────────────┘
                                │
                       ┌────────▼────────┐
                       │   ChromaDB      │
                       │ (Vector Store)  │
                       └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- 4GB RAM, 10GB+ disk

```bash
git clone <repository-url>
cd vectorguard
chmod +x scripts/setup.sh
./scripts/setup.sh
```

- Frontend: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Manual Setup

```bash
cp .env.example .env
docker-compose up -d
docker-compose exec backend python -c "from src.database.connection import init_db; init_db()"
```

## Usage

### Web Interface

Natural language queries like:
- `critical vulnerabilities in Apache`
- `recent CVEs affecting Linux kernel`
- `security advisories from Microsoft this month`

Apply filters for severity, date range, and content type.

### API

```bash
# Search threat intelligence
curl -X POST http://localhost:8000/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "critical vulnerabilities", "limit": 10}'

# Recent CVEs
curl http://localhost:8000/api/cves/recent?limit=20

# Trigger ingestion
curl -X POST http://localhost:8000/api/ingestion/trigger/cve
```

## Configuration

```bash
DATABASE_URL=postgresql+psycopg2://vectorguard:changeme@localhost:5432/vectorguard
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key-here-change-in-production
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
CHROMA_PERSIST_DIRECTORY=./chroma_data
```

## Data Sources

| Source | Content |
|--------|---------|
| NVD | CVE database |
| CISA | Security advisories |
| US-CERT | Current cyber activity |
| Microsoft MSRC | Security advisories |
| Apple Security | Security updates |
| Red Hat | Security advisories |

## API Reference

| Endpoint | Description |
|----------|-------------|
| `POST /api/search` | Semantic search |
| `GET /api/search/suggestions` | Query suggestions |
| `GET /api/cves/{cve_id}` | CVE detail |
| `GET /api/cves/recent` | Recent CVEs |
| `GET /api/cves/severity/{severity}` | CVEs by severity |
| `GET /api/advisories` | Security advisories |
| `POST /api/ingestion/trigger/{type}` | Manual ingestion |
| `GET /health` | System health |

## Development

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn src.api.app:app --reload

# Frontend
cd frontend
npm install && npm run dev

# Tests
cd backend && pytest
cd frontend && npm test

# Linting
black . && ruff check . && mypy .
```

## Security

- JWT + API key authentication
- Role-based access control
- HTTPS required in production
- Rate limiting and CORS configuration
- Input validation on all endpoints

## License

MIT — see [LICENSE](LICENSE) for details.

## Author

**Daniel Gregg Jr**

[LinkedIn](https://linkedin.com/in/daniel-sin-1881ske89)
