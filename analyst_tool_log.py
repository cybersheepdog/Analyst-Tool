# Analyst Tool — diagnostics log
#
# Before this module the tool ran `logging.disable(sys.maxsize)` at import, so
# nothing — not a swallowed KeyError in a service module, not a psycopg2
# disconnect — was ever recorded anywhere, and the main loop's catch-all
# printed nothing. Now:
#
#   * `analyst_tool.log` (rotating, 5 × 1 MB, next to config.ini) receives one
#     line per lookup (indicator, kind, elapsed, which services were
#     unavailable) and a full traceback for every error the tool recovers
#     from. Set [GENERAL] log_file = (blank) to turn the file off.
#   * The console gets a one-line "[error] KeyError: 'data'" instead of
#     silence.
#   * Third-party loggers (taxii2client, urllib3, elasticsearch, pycti…) are
#     pinned to CRITICAL so they never write to the console, which is what the
#     old global disable was really for.
#
# The log holds indicators you looked up — treat it like the cache database.

import logging
import logging.handlers
import os
from configparser import ConfigParser

LOGGER_NAME = 'analyst'
DEFAULT_LOG_FILE = 'analyst_tool.log'

# Libraries that log chatter at INFO/WARNING which would otherwise reach the
# console through Python's last-resort handler.
_NOISY = ('taxii2client', 'stix2', 'urllib3', 'requests', 'elasticsearch',
          'elastic_transport', 'pycti', 'asyncio', 'charset_normalizer',
          'attackcti', 'OTXv2', 'shodan')

_configured = False


def _log_file_from_config(path="config.ini"):
    # ANALYST_TOOL_LOG overrides config.ini (blank = no file); the test suite
    # sets it blank so running pytest never writes a log into the repo.
    env = os.environ.get("ANALYST_TOOL_LOG")
    if env is not None:
        return env.strip()
    try:
        cfg = ConfigParser()
        cfg.read(path)
        return cfg.get("GENERAL", "log_file", fallback=DEFAULT_LOG_FILE).strip()
    except Exception:
        return DEFAULT_LOG_FILE


def setup_logging(log_file=None):
    """Configure the tool's logger once. Safe to call repeatedly."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    if _configured:
        return logger
    _configured = True

    # Quiet everything that isn't ours, without disabling logging globally.
    root = logging.getLogger()
    root.setLevel(logging.CRITICAL)
    if not root.handlers:
        root.addHandler(logging.NullHandler())
    for name in _NOISY:
        logging.getLogger(name).setLevel(logging.CRITICAL)

    logger.setLevel(logging.INFO)
    logger.propagate = False
    if log_file is None:
        log_file = _log_file_from_config()
    if log_file:
        try:
            handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=1_000_000, backupCount=5, encoding='utf-8',
                delay=True)   # file is created on the first record, not at import
            handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)-7s %(threadName)s %(message)s'))
            logger.addHandler(handler)
        except Exception:
            # Unwritable location (read-only share, permissions): run without
            # a file rather than refuse to start.
            logger.addHandler(logging.NullHandler())
    else:
        logger.addHandler(logging.NullHandler())
    return logger


def get_logger():
    """The tool's logger; configures it on first use."""
    return setup_logging() if not _configured else logging.getLogger(LOGGER_NAME)


def report_error(where, exc, console=True):
    """Record a recovered exception: traceback to the log, one line to the
    console (unless console=False). Never raises."""
    try:
        get_logger().exception("%s: %s: %s", where, type(exc).__name__, exc)
    except Exception:
        pass
    if console:
        try:
            print("\t[error] %s: %s  (details in %s)"
                  % (type(exc).__name__, exc, _log_file_from_config() or "the log"))
        except Exception:
            pass
