"""
Centralized logger. Import get_logger() in every module.

Usage:
    from core.logger import get_logger
    log = get_logger(__name__)
    log.info("Crawling started")
"""

import logging
import os
import sys
from config import LOG_DIR, LOG_LEVEL


class SafeStreamHandler(logging.StreamHandler):
    """Swallows OSError so background threads never crash on a closed stream."""
    def emit(self, record):
        try:
            super().emit(record)
        except OSError:
            pass

    def flush(self):
        try:
            super().flush()
        except OSError:
            pass


def get_logger(name: str) -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)

    # Replace any old StreamHandlers with SafeStreamHandler
    for h in logger.handlers[:]:
        if type(h) is logging.StreamHandler:  # exact type, not subclass
            logger.removeHandler(h)

    # If handlers already set up correctly, return as-is
    if any(isinstance(h, SafeStreamHandler) for h in logger.handlers):
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    ch = SafeStreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
        fh = logging.FileHandler(os.path.join(LOG_DIR, "scanner.log"))
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
