"""Shared environment semantics for Yggflare application settings."""

import os


def env_get(env, name, default=None):
    """Treat a literal empty string exactly like an absent setting."""
    value = env.get(name, default)
    return default if value == "" else value


def getenv(name, default=None):
    """Read the current process environment without modifying it."""
    return env_get(os.environ, name, default)


def env_required(env, name):
    """Required settings reject absence and empty strings identically."""
    value = env[name]
    if value == "":
        raise KeyError(name)
    return value
