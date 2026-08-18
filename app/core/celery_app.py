from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "security_ai",
    broker=settings.celery_broker_url,
    include=[
        "app.tasks.investigation_reports",
    ],
)


celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    task_ignore_result=True,

    timezone="UTC",
    enable_utc=True,

    broker_connection_retry_on_startup=True,

    task_default_queue="security-ai",

    task_track_started=False,
)

