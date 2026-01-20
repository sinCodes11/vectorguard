import os
from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import time

from src.database.connection import get_db
from src.models.schemas import (
    SearchQuery, SearchResponse, SearchResult, ErrorResponse,
    HealthResponse, CVECreate, CVEUpdate, IngestionJobCreate,
    CVEDetails, Advisory as PydanticAdvisory, IngestionJob as PydanticIngestionJob
)
from src.rag.search_service import RAGPipeline
from src.ingestion.tasks import cve_ingestion_task, advisory_ingestion_task, generate_embeddings_task
from src.ingestion.cve_service import CVEIngestionService
from src.ingestion.advisory_service import AdvisoryIngestionService
from src.rag.embedding_service import EmbeddingService
from src.models.database import CVE, Advisory, IngestionJob
from src.models.auth import User
from src.api.dependencies import get_current_user_optional, get_current_user_required
from sqlalchemy import func, desc

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VectorGuard API",
    description="RAG-Powered Threat Intelligence Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Include authentication routes
from src.api.auth_routes import router as auth_router
app.include_router(auth_router)

# CORS middleware - configure allowed origins from environment
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Simple in-memory rate limiter
class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        minute_ago = now - 60

        # Clean old requests
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip]
            if req_time > minute_ago
        ]

        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return False

        self.requests[client_ip].append(now)
        return True

rate_limiter = RateLimiter(requests_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"

    # Skip rate limiting for health checks
    if request.url.path == "/health":
        return await call_next(request)

    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "message": "Too many requests. Please try again later."}
        )

    return await call_next(request)

# Initialize services with error handling
try:
    logger.info("Initializing services...")
    rag_pipeline = RAGPipeline()
    embedding_service = EmbeddingService()
    cve_service = CVEIngestionService()
    advisory_service = AdvisoryIngestionService()
    logger.info("Services initialized successfully")
except Exception as e:
    logger.error(f"Error initializing services: {e}")
    logger.warning("Some services may not be available. Check logs for details.")
    # Create placeholder services to prevent crashes
    rag_pipeline = None
    embedding_service = None
    cve_service = None
    advisory_service = None


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    try:
        from src.database.init_db import initialize_database
        logger.info("Running database initialization...")
        initialize_database()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        logger.warning("Application may not function correctly without database")


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "VectorGuard API",
        "description": "RAG-Powered Threat Intelligence Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        # Check database connectivity
        db = next(get_db())
        db.execute(text("SELECT 1"))
        db.close()
        
        # Check embedding service
        embedding_stats = embedding_service.get_embedding_stats()
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow(),
            version="1.0.0",
            services={
                "database": "healthy",
                "embedding_service": "healthy",
                "total_embeddings": str(embedding_stats["total_embeddings"])
            }
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthResponse(
            status="unhealthy",
            timestamp=datetime.utcnow(),
            version="1.0.0",
            services={"database": "unhealthy"}
        )

@app.post("/api/search", response_model=SearchResponse)
async def search(
    query_data: SearchQuery,
    db: Session = Depends(get_db)
):
    """Search threat intelligence using RAG pipeline."""
    if rag_pipeline is None:
        raise HTTPException(
            status_code=503,
            detail="Search service is not available. Please check server logs."
        )

    try:
        result = await rag_pipeline.search(
            db=db,
            query=query_data.query,
            limit=query_data.limit,
            severity_filter=query_data.severity_filter,
            date_range=query_data.date_range,
            content_types=query_data.content_types
        )
        return result
    except Exception as e:
        logger.error(f"Search error: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@app.get("/api/search/suggestions", response_model=List[str])
async def get_search_suggestions(
    q: str = Query(..., min_length=1, description="Partial query for suggestions"),
    db: Session = Depends(get_db)
):
    """Get search suggestions for partial query."""
    try:
        suggestions = await rag_pipeline.get_search_suggestions(db, q)
        return suggestions
    except Exception as e:
        logger.error(f"Suggestions error: {e}")
        return []

@app.get("/api/search/stats")
async def get_search_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days for stats"),
    db: Session = Depends(get_db)
):
    """Get search statistics."""
    try:
        stats = rag_pipeline.get_search_stats(db, days)
        return stats
    except Exception as e:
        logger.error(f"Search stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get search stats")

# CVE endpoints
@app.get("/api/cves/{cve_id}", response_model=CVEDetails)
async def get_cve(
    cve_id: str,
    db: Session = Depends(get_db)
):
    """Get specific CVE by ID."""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return CVEDetails.from_orm(cve)

@app.get("/api/cves/recent", response_model=List[CVEDetails])
async def get_recent_cves(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get recent CVEs."""
    cves = db.query(CVE).order_by(desc(CVE.published_date)).limit(limit).all()
    return [CVEDetails.from_orm(cve) for cve in cves]

@app.get("/api/cves/severity/{severity}", response_model=List[CVEDetails])
async def get_cves_by_severity(
    severity: str,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get CVEs by severity level."""
    cves = db.query(CVE).filter(
        CVE.severity == severity.upper()
    ).order_by(desc(CVE.published_date)).limit(limit).all()
    return [CVEDetails.from_orm(cve) for cve in cves]

@app.get("/api/cves/stats")
async def get_cve_stats(db: Session = Depends(get_db)):
    """Get CVE statistics."""
    try:
        total_cves = db.query(CVE).count()
        
        severity_counts = db.query(
            CVE.severity, func.count(CVE.id)
        ).group_by(CVE.severity).all()
        
        latest_cve = db.query(CVE).order_by(desc(CVE.published_date)).first()
        
        return {
            "total_cves": total_cves,
            "severity_distribution": dict(severity_counts),
            "latest_cve_date": latest_cve.published_date if latest_cve else None
        }
    except Exception as e:
        logger.error(f"CVE stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get CVE stats")

# Advisory endpoints
@app.get("/api/advisories", response_model=List[PydanticAdvisory])
async def get_advisories(
    source: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get security advisories with optional filtering."""
    query = db.query(Advisory)
    
    if source:
        query = query.filter(Advisory.source == source.upper())
    if severity:
        query = query.filter(Advisory.severity == severity.upper())
    
    advisories = query.order_by(desc(Advisory.published_date)).limit(limit).all()
    return [PydanticAdvisory.from_orm(advisory) for advisory in advisories]

@app.get("/api/advisories/{advisory_id}", response_model=PydanticAdvisory)
async def get_advisory(
    advisory_id: int,
    db: Session = Depends(get_db)
):
    """Get specific advisory by ID."""
    advisory = db.query(Advisory).filter(Advisory.id == advisory_id).first()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return PydanticAdvisory.from_orm(advisory)

@app.get("/api/advisories/stats")
async def get_advisory_stats(db: Session = Depends(get_db)):
    """Get advisory statistics."""
    try:
        total_advisories = db.query(Advisory).count()
        
        source_counts = db.query(
            Advisory.source, func.count(Advisory.id)
        ).group_by(Advisory.source).all()
        
        severity_counts = db.query(
            Advisory.severity, func.count(Advisory.id)
        ).filter(Advisory.severity.isnot(None)).group_by(Advisory.severity).all()
        
        return {
            "total_advisories": total_advisories,
            "source_distribution": dict(source_counts),
            "severity_distribution": dict(severity_counts)
        }
    except Exception as e:
        logger.error(f"Advisory stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get advisory stats")

# Ingestion endpoints (protected - requires authentication)
@app.post("/api/ingestion/trigger/{ingestion_type}")
async def trigger_ingestion(
    ingestion_type: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """Trigger manual ingestion of threat intelligence data (requires authentication if enabled)."""
    if ingestion_type not in ["cve", "advisory"]:
        raise HTTPException(status_code=400, detail="Invalid ingestion type")
    
    try:
        if ingestion_type == "cve":
            task = cve_ingestion_task.delay(hours_back=24)
        else:
            task = advisory_ingestion_task.delay()
        
        return {
            "message": f"{ingestion_type} ingestion triggered",
            "task_id": task.id,
            "status": "queued"
        }
    except Exception as e:
        logger.error(f"Ingestion trigger error: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger ingestion")

@app.get("/api/ingestion/jobs", response_model=List[PydanticIngestionJob])
async def get_ingestion_jobs(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get recent ingestion jobs."""
    jobs = db.query(IngestionJob).order_by(
        desc(IngestionJob.created_at)
    ).limit(limit).all()
    return [PydanticIngestionJob.from_orm(job) for job in jobs]

@app.get("/api/ingestion/stats")
async def get_ingestion_stats(db: Session = Depends(get_db)):
    """Get ingestion statistics."""
    try:
        total_jobs = db.query(IngestionJob).count()
        
        status_counts = db.query(
            IngestionJob.status, func.count(IngestionJob.id)
        ).group_by(IngestionJob.status).all()
        
        recent_jobs = db.query(IngestionJob).filter(
            IngestionJob.created_at >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        return {
            "total_jobs": total_jobs,
            "status_distribution": dict(status_counts),
            "recent_jobs": recent_jobs
        }
    except Exception as e:
        logger.error(f"Ingestion stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get ingestion stats")

# Embedding endpoints
@app.post("/api/embeddings/generate")
async def generate_embeddings(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Generate embeddings for new content."""
    try:
        task = generate_embeddings_task.delay()
        return {
            "message": "Embedding generation triggered",
            "task_id": task.id,
            "status": "queued"
        }
    except Exception as e:
        logger.error(f"Embedding generation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger embedding generation")

@app.get("/api/embeddings/stats")
async def get_embedding_stats():
    """Get embedding statistics."""
    try:
        stats = embedding_service.get_embedding_stats()
        return stats
    except Exception as e:
        logger.error(f"Embedding stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get embedding stats")

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "message": "An unexpected error occurred"}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "HTTP error", "message": exc.detail}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)