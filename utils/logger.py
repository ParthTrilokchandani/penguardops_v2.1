"""Centralized colored logging."""

import logging
import sys
from typing import Optional

COLORS = {
    "DEBUG":    "\033[36m",   # Cyan
    "INFO":     "\033[32m",   # Green
    "WARNING":  "\033[33m",   # Yellow
    "ERROR":    "\033[31m",   # Red
    "CRITICAL": "\033[35m",   # Magenta
}
RESET = "\033[0m"
BOLD  = "\033[1m"

_loggers = {}


class ColorFormatter(logging.Formatter):
    def format(self, record):
        color = COLORS.get(record.levelname, "")
        name_color = "\033[34m"  # Blue for logger name
        return (
            f"{color}[{record.levelname[0]}]{RESET} "
            f"{name_color}[{record.name}]{RESET} "
            f"{record.getMessage()}"
        )


def get_logger(name: str) -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(f"vulnscan.{name}")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColorFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    _loggers[name] = logger
    return logger
