import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base application configuration."""

    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload settings
    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER",
        str(BASE_DIR / "instance" / "uploads")
    )
    MAX_CONTENT_LENGTH = int(
        os.environ.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024)
    )
    ALLOWED_EXTENSIONS = {
        "pdf", "docx", "txt", "png", "jpg", "jpeg", "csv", "xlsx"
    }

    # Session and security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-only-secret-change-before-deployment"
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'instance' / 'trustvault.db'}"
    )


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DEBUG = False
    SECRET_KEY = "test-only-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    UPLOAD_FOLDER = str(BASE_DIR / "instance" / "test_uploads")


class ProductionConfig(Config):
    """Production configuration with secure cookie settings."""

    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")

    @staticmethod
    def init_app(app):
        """Reject production startup when required secrets are missing."""
        if not app.config.get("SECRET_KEY"):
            raise RuntimeError(
                "SECRET_KEY must be set in production."
            )

        if not app.config.get("SQLALCHEMY_DATABASE_URI"):
            raise RuntimeError(
                "DATABASE_URL must be set in production."
            )


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}