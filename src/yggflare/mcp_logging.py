"""Route HTTP SDK diagnostics through the controller without exposing payloads."""

import logging
from contextlib import contextmanager

LIFECYCLE_MESSAGES = frozenset(
    {
        "StreamableHTTP session manager started",
        "StreamableHTTP session manager shutting down",
        "StreamableHTTP session manager stopped",
    }
)


class HTTPLogHandler(logging.Handler):
    """Allow fixed lifecycle text only; never format untrusted SDK log arguments."""

    def __init__(self, sink):
        super().__init__(logging.INFO)
        self.sink = sink

    def emit(self, record):
        if record.name == "uvicorn.access" or record.name.startswith("uvicorn.access."):
            return
        if record.levelno >= logging.CRITICAL:
            level = "critical"
        elif record.levelno >= logging.ERROR:
            level = "error"
        elif record.levelno >= logging.WARNING:
            level = "warning"
        else:
            level = "info"
        if (
            isinstance(record.msg, str)
            and record.msg in LIFECYCLE_MESSAGES
            and not record.args
            and not record.exc_info
        ):
            message = record.msg
        elif record.levelno >= logging.WARNING:
            source = "Uvicorn" if record.name.startswith("uvicorn") else "MCP SDK"
            message = f"{source} diagnostic (details omitted)"
        else:
            # Request-level SDK informational messages may contain private data.
            return
        self.sink(level, "mcp", message)


@contextmanager
def http_logging(sink):
    """Scope routing to the HTTP listener lifetime, not the root logger or stdio."""
    roots = {"mcp": logging.INFO, "uvicorn": logging.WARNING}
    for name in roots:
        logging.getLogger(name)
    handler = HTTPLogHandler(sink)
    saved = []
    # The SDK and Uvicorn may already have installed descendant handlers.
    # Route each namespace once, avoiding propagation to the root logger.
    for name, logger in list(logging.Logger.manager.loggerDict.items()):
        root = name.split(".", 1)[0]
        if root not in roots or not isinstance(logger, logging.Logger):
            continue
        saved.append(
            (logger, logger.handlers[:], logger.level, logger.propagate, logger.disabled)
        )
        logger.handlers = [handler] if name == root else []
        logger.setLevel(roots[root] if name == root else logging.NOTSET)
        logger.propagate = name != root
        logger.disabled = False
    try:
        yield
    finally:
        for logger, handlers, level, propagate, disabled in saved:
            logger.handlers = handlers
            logger.setLevel(level)
            logger.propagate = propagate
            logger.disabled = disabled
        handler.close()
