import threading

from app.scan_jobs import run_scan_job


def enqueue_scan_job(scan_id, target, app):
    if app.config.get("SCAN_QUEUE_BACKEND", "thread") == "rq":
        job_id = _enqueue_with_rq(scan_id=scan_id, target=target, app=app)
        if job_id:
            return {"backend": "rq", "job_id": job_id}

    thread = threading.Thread(target=run_scan_job, args=(scan_id, target), daemon=True)
    thread.start()
    return {"backend": "thread", "job_id": None}


def _enqueue_with_rq(scan_id, target, app):
    redis_url = app.config.get("REDIS_URL")
    if not redis_url:
        return None

    try:
        from redis import Redis
        from rq import Queue
    except Exception:
        app.logger.warning("RQ backend requested but redis/rq packages are unavailable; using thread fallback")
        return None

    try:
        queue_name = app.config.get("RQ_QUEUE_NAME", "vtr_scans")
        connection = Redis.from_url(redis_url)
        queue = Queue(queue_name, connection=connection)
        job = queue.enqueue(
            "app.scan_jobs.run_scan_job",
            scan_id,
            target,
            job_timeout=app.config.get("SCAN_JOB_TIMEOUT_SECONDS", 900),
        )
        return job.id
    except Exception:
        app.logger.exception("Failed to enqueue scan job in RQ; using thread fallback")
        return None
