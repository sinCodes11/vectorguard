from celery import Task
from src.database.celery_app import celery_app
from src.ingestion.cve_service import CVEIngestionService
from src.ingestion.advisory_service import AdvisoryIngestionService
from src.models.database import IngestionJob
from src.database.connection import get_db
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class IngestionTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"Task {task_id} failed: {exc}")
        
    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"Task {task_id} completed successfully")


@celery_app.task(bind=True, base=IngestionTask)
def cve_ingestion_task(self, hours_back: int = 24):
    """Background task to ingest CVE data."""

    db = next(get_db())
    service = CVEIngestionService()

    # Create ingestion job record
    job = IngestionJob(
        job_type="cve_ingestion",
        source="NVD",
        status="running",
        started_at=datetime.utcnow(),
        job_metadata={"hours_back": hours_back}
    )
    db.add(job)
    db.commit()

    try:
        # Use fixed date range with actual CVE data (recent past dates)
        from datetime import timedelta
        start_date = datetime(2024, 12, 1)
        end_date = datetime(2025, 1, 15)

        import asyncio
        result = asyncio.run(service.ingest_cves(db, start_date=start_date, end_date=end_date))
        
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        job.items_processed = result["processed"]
        job.items_failed = result["failed"]
        
        db.commit()
        
        return {
            "job_id": job.id,
            "processed": result["processed"],
            "failed": result["failed"]
        }
        
    except Exception as e:
        job.status = "failed"
        job.completed_at = datetime.utcnow()
        job.error_message = str(e)
        db.commit()
        
        logger.error(f"CVE ingestion task failed: {e}")
        raise
        
    finally:
        db.close()


@celery_app.task(bind=True, base=IngestionTask)
def advisory_ingestion_task(self):
    """Background task to ingest security advisories."""
    
    db = next(get_db())
    service = AdvisoryIngestionService()
    
    # Create ingestion job record
    job = IngestionJob(
        job_type="advisory_ingestion",
        source="multiple",
        status="running",
        started_at=datetime.utcnow()
    )
    db.add(job)
    db.commit()
    
    try:
        import asyncio
        result = asyncio.run(service.ingest_all_advisories(db))
        
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        job.items_processed = result["processed"]
        job.items_failed = result["failed"]
        
        db.commit()
        
        return {
            "job_id": job.id,
            "processed": result["processed"],
            "failed": result["failed"]
        }
        
    except Exception as e:
        job.status = "failed"
        job.completed_at = datetime.utcnow()
        job.error_message = str(e)
        db.commit()
        
        logger.error(f"Advisory ingestion task failed: {e}")
        raise
        
    finally:
        db.close()


@celery_app.task
def generate_embeddings_task():
    """Background task to generate vector embeddings for new content."""
    
    from src.rag.embedding_service import EmbeddingService
    
    db = next(get_db())
    service = EmbeddingService()
    
    try:
        import asyncio
        result = asyncio.run(service.generate_embeddings_for_new_content(db))
        
        logger.info(f"Generated embeddings: {result['processed']} processed, {result['failed']} failed")
        return result
        
    except Exception as e:
        logger.error(f"Embedding generation task failed: {e}")
        raise
        
    finally:
        db.close()