# core/logger.py
"""
Centralized logger. Import get_logger() in every module.

Usage:
    from core.logger import get_logger
    log = get_logger(__name__)
    log.info("Crawling started")
"""

import logging
import os
from config import LOG_DIR, LOG_LEVEL


def get_logger(name: str) -> logging.Logger:
    """
    Returns a named logger that writes to both console and file.
    Call once per module with get_logger(__name__).
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if get_logger is called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler — you see this in your terminal
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler — persists across runs
    fh = logging.FileHandler(os.path.join(LOG_DIR, "scanner.log"))
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger