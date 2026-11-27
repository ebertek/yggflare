"""Opt-in operator progress on stderr; never alter structured stdout."""

import sys
import time
from contextlib import contextmanager
from contextvars import ContextVar

START = ContextVar("retirement_progress_start", default=None)


@contextmanager
def reporting():
    token = START.set(time.monotonic())
    try:
        yield
    finally:
        START.reset(token)


def emit(message):
    start = START.get()
    if start is not None:
        print(f"[retirement +{time.monotonic() - start:.1f}s] {message}", file=sys.stderr, flush=True)
