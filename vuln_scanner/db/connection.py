# db/connection.py
"""
PostgreSQL connection pool for WASP.
Reads DATABASE_URL from .env — set it before first use.

    DATABASE_URL=postgresql://user:password@localhost:5432/wasp
"""

import os
import logging
from contextlib import contextmanager

try:
    import psycopg2
    from psycopg2 import pool as pg_pool
    from psycopg2.extras import RealDictCursor
except ImportError:
    raise ImportError(
        "psycopg2 is required for database support.\n"
        "Install it with:  pip install psycopg2-binary"
    )

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

log = logging.getLogger("wasp.db")

_pool: pg_pool.ThreadedConnectionPool | None = None


def init_pool(min_conn: int = 1, max_conn: int = 10) -> None:
    """
    Initialise the connection pool.
    Called once at application startup (app.py / main.py).
    """
    global _pool

    url = os.getenv("DATABASE_URL")
    if not url:
        raise EnvironmentError(
            "DATABASE_URL not set.\n"
            "Add it to your .env file:\n"
            "  DATABASE_URL=postgresql://user:password@localhost:5432/wasp"
        )

    _pool = pg_pool.ThreadedConnectionPool(min_conn, max_conn, dsn=url)
    log.info("PostgreSQL connection pool initialised (min=%d, max=%d)", min_conn, max_conn)


@contextmanager
def get_conn():
    """
    Context manager that yields a psycopg2 connection from the pool
    and returns it when the block exits (commit on success, rollback on error).

    Usage:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(...)
    """
    global _pool
    if _pool is None:
        init_pool()

    conn = _pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)


def close_pool() -> None:
    """Shutdown — call on application teardown."""
    global _pool
    if _pool:
        _pool.closeall()
        _pool = None
        log.info("PostgreSQL connection pool closed")