# VectorGuard: RAG-Powered Threat Intelligence Platform

A self-hosted threat intelligence knowledge base that ingests CVE databases and security advisories with natural language querying via RAG pipeline.

## 🛡️ Features

- **Real-time Ingestion**: Automated ingestion from NVD, CISA, US-CERT, and other security sources
- **RAG-Powered Search**: Natural language queries with semantic understanding and relevance ranking
- **Vector Embeddings**: Advanced similarity search using sentence-transformers and ChromaDB
- **CVE Database**: Comprehensive vulnerability database with CVSS scores and analysis
- **Security Advisories**: Multi-source security advisory aggregation
- **REST API**: Full programmatic access with authentication
- **Web Interface**: Modern, responsive search interface
- **Self-Hosted**: Complete Docker deployment with all components

## 🏗️ Architecture

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
                │            │    │            │
                └────────────┘    └────────────┘
                                │
                       ┌────────▼────────┐
                       │   ChromaDB      │
                       │ (Vector Store)  │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- At least 4GB RAM
- 10GB+ disk space for data

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd vectorguard
```

2. **Run the setup script:**
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

3. **Access the application:**
- Frontend: http://localhost:3000
- API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

### Manual Setup

1. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

2. **Start services:**
```bash
docker-compose up -d
```

3. **Initialize database:**
```bash
docker-compose exec backend python -c "from src.database.connection import init_db; init_db()"
```

## 📊 Usage

### Web Interface

1. Visit http://localhost:3000
2. Use natural language queries like:
   - "critical vulnerabilities in Apache"
   - "recent CVEs affecting Linux"
   - "security advisories from Microsoft"
3. Apply filters for severity, date range, and content types

### API Access

```bash
# Search threat intelligence
curl -X POST http://localhost:8000/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "critical vulnerabilities", "limit": 10}'

# Get recent CVEs
curl http://localhost:8000/api/cves/recent?limit=20

# Get security advisories
curl http://localhost:8000/api/advisories

# Trigger data ingestion
curl -X POST http://localhost:8000/api/ingestion/trigger/cve
curl -X POST http://localhost:8000/api/ingestion/trigger/advisory
```

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Database
DATABASE_URL=postgresql+psycopg2://vectorguard:changeme@localhost:5432/vectorguard
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=your-secret-key-here-change-in-production

# Embeddings
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
CHROMA_PERSIST_DIRECTORY=./chroma_data
```

### Data Sources

The platform ingests data from:
- **NVD (National Vulnerability Database)**: CVE data
- **CISA**: Security advisories
- **US-CERT**: Current cyber activity
- **Microsoft Security Response Center**: Security advisories
- **Apple Security**: Security updates
- **Red Hat**: Security advisories

## 📈 Scaling

### High Availability

For production deployment:

1. **Database Scaling:**
   - Use managed PostgreSQL service
   - Configure read replicas
   - Implement connection pooling

2. **Vector Store Scaling:**
   - Deploy ChromaDB in cluster mode
   - Consider alternative vector databases (Pinecone, Weaviate)

3. **API Scaling:**
   - Load balance multiple API instances
   - Configure Redis for session storage
   - Implement rate limiting

4. **Ingestion Scaling:**
   - Deploy multiple Celery workers
   - Configure queues by priority
   - Monitor and auto-scale based on load

## 🔍 API Documentation

### Search Endpoints

- `POST /api/search` - Main search endpoint
- `GET /api/search/suggestions` - Search suggestions
- `GET /api/search/stats` - Search statistics

### CVE Endpoints

- `GET /api/cves/{cve_id}` - Get specific CVE
- `GET /api/cves/recent` - Get recent CVEs
- `GET /api/cves/severity/{severity}` - Get CVEs by severity
- `GET /api/cves/stats` - CVE statistics

### Advisory Endpoints

- `GET /api/advisories` - Get advisories (with filtering)
- `GET /api/advisories/{id}` - Get specific advisory
- `GET /api/advisories/stats` - Advisory statistics

### Ingestion Endpoints

- `POST /api/ingestion/trigger/{type}` - Trigger manual ingestion
- `GET /api/ingestion/jobs` - Get ingestion jobs
- `GET /api/ingestion/stats` - Ingestion statistics

## 🔒 Security

### Authentication

The platform supports:
- JWT token authentication
- API key authentication
- User session management

### Authorization

- Role-based access control
- API key permissions
- Resource-level security

### Best Practices

1. **Production Deployment:**
   - Use HTTPS
   - Set strong SECRET_KEY
   - Configure firewalls
   - Regular updates

2. **API Security:**
   - Rate limiting
   - Input validation
   - CORS configuration
   - Request logging

## 📝 Development

### Local Development

1. **Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.api.app:app --reload
```

2. **Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

### Code Quality

```bash
# Backend linting
cd backend
black .
ruff check .
mypy .

# Frontend linting
cd frontend
npm run lint
npm run type-check
```

## 📊 Monitoring

### Health Checks

- `GET /health` - Overall system health
- Component status monitoring
- Database connectivity checks

### Metrics

- Search performance metrics
- Ingestion job statistics
- API response times
- Error rates

### Logging

- Structured logging with correlation IDs
- Log levels: DEBUG, INFO, WARNING, ERROR
- Log aggregation recommendations

## 🛠️ Troubleshooting

### Common Issues

1. **Service won't start:**
   ```bash
   # Check logs
   docker-compose logs [service]
   
   # Restart services
   docker-compose restart
   ```

2. **Database connection errors:**
   ```bash
   # Check database status
   docker-compose exec postgres pg_isready
   
   # Recreate database
   docker-compose down postgres
   docker-compose up -d postgres
   ```

3. **Embedding generation issues:**
   ```bash
   # Check ChromaDB status
   docker-compose logs backend | grep -i chroma
   
   # Regenerate embeddings
   curl -X POST http://localhost:8000/api/embeddings/generate
   ```

### Performance Tuning

1. **Database Optimization:**
   - Index important query fields
   - Analyze query performance
   - Configure connection pooling

2. **Vector Search Optimization:**
   - Tune embedding model
   - Adjust similarity thresholds
   - Optimize ChromaDB settings

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review troubleshooting section

---

**VectorGuard** - Empowering security teams with AI-driven threat intelligence.