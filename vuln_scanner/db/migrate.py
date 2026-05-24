# db/migrate.py
"""
WASP database migration runner.
Run this once to create (or update) all tables:
    python -m db.migrate
Or call run_migrations() from your app startup code.
"""
import logging
import sys
import os


def _safe_print(msg):
    try:
        print(msg)
        sys.stdout.flush()
    except OSError:
        pass


from core.logger import get_logger
log = get_logger("wasp.db.migrate")


def run_migrations() -> None:
    """
    Execute the full WASP schema SQL against the configured database.
    Safe to run multiple times — all statements use IF NOT EXISTS /
    CREATE OR REPLACE so existing data is never dropped.
    """
    from .connection import get_conn
    from .models     import SCHEMA_SQL

    log.info("Running WASP database migrations...")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
    log.info("Migrations complete.")
    _safe_print("✓ WASP database schema applied successfully.")


if __name__ == "__main__":
    # Allow:  python -m db.migrate
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    )
    # Add project root to path so relative imports work
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, project_root)
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(project_root, ".env"))
    except ImportError:
        pass
    run_migrations()