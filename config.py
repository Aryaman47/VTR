import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(2 * 1024 * 1024)))
    SCAN_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("SCAN_RATE_LIMIT_WINDOW_SECONDS", "60"))
    SCAN_RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("SCAN_RATE_LIMIT_MAX_REQUESTS", "5"))
    CVE_ENRICHMENT_ENABLED = os.environ.get("CVE_ENRICHMENT_ENABLED", "1") == "1"
    NVD_API_KEY = os.environ.get("NVD_API_KEY")
    NVD_API_TIMEOUT_SECONDS = int(os.environ.get("NVD_API_TIMEOUT_SECONDS", "10"))
    NVD_RESULTS_PER_QUERY = int(os.environ.get("NVD_RESULTS_PER_QUERY", "5"))
    NVD_MAX_QUERIES_PER_SERVICE = int(os.environ.get("NVD_MAX_QUERIES_PER_SERVICE", "3"))
    SCAN_QUEUE_BACKEND = os.environ.get("SCAN_QUEUE_BACKEND", "thread")
    REDIS_URL = os.environ.get("REDIS_URL")
    RQ_QUEUE_NAME = os.environ.get("RQ_QUEUE_NAME", "vtr_scans")
    SCAN_JOB_TIMEOUT_SECONDS = int(os.environ.get("SCAN_JOB_TIMEOUT_SECONDS", "900"))
    VTR_ADMIN_USERNAME = os.environ.get("VTR_ADMIN_USERNAME", "admin")
    VTR_ADMIN_PASSWORD = os.environ.get("VTR_ADMIN_PASSWORD", "admin123")


class DevelopmentConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "app", "database.db"),
    )
    DEBUG = True


class ProductionConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    DEBUG = False

    @classmethod
    def validate(cls):
        if not cls.SQLALCHEMY_DATABASE_URI:
            raise RuntimeError("DATABASE_URL must be set for ProductionConfig")

class TestingConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    TESTING = True
