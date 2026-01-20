from celery import Celery
from src.core.config import settings

celery_app = Celery(
    "vectorguard",
    broker=str(settings.REDIS_URL),
    backend=str(settings.REDIS_URL),
    include=["src.ingestion.tasks"]
)

celery_app.conf.update(
    task_track_started=True,
    task_time_limit=3600, # 1 hour
    broker_connection_retry_on_startup=True
)

# Optional: Configure Celery Beat for periodic tasks
# celery_app.conf.beat_schedule = {
#     'ingest-nvd-daily': {
#         'task': 'src.services.ingestion_service.ingest_nvd_data',
#         'schedule': timedelta(days=1), # Run daily
#     },
# }
