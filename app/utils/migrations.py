import logging
from sqlalchemy import text
from app.extensions import db

logger = logging.getLogger(__name__)

def apply_db_migrations():
    """
    Apply safe, idempotent schema updates for SQLite databases.
    Ensures newly added columns are automatically created if an existing database
    was initialized prior to model updates.
    """
    try:
        db.create_all()

        engine = db.engine
        if engine.dialect.name == 'sqlite':
            with engine.connect() as conn:
                # 1. Users table migrations
                result = conn.execute(text("PRAGMA table_info(users)"))
                user_cols = {row[1] for row in result.fetchall()}

                if 'failed_login_attempts' not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0 NOT NULL"))
                    conn.commit()

                if 'locked_until' not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN locked_until DATETIME"))
                    conn.commit()

                # 2. Documents table migrations
                result = conn.execute(text("PRAGMA table_info(documents)"))
                doc_cols = {row[1] for row in result.fetchall()}

                if 'sha256_checksum' not in doc_cols:
                    conn.execute(text("ALTER TABLE documents ADD COLUMN sha256_checksum VARCHAR(64)"))
                    conn.commit()

    except Exception as e:
        logger.warning(f"Database migration check notice: {e}")
