"""Cached boto3 session/clients and region resolution.

Credentials come from the standard boto3 provider chain (env vars, shared config,
SSO, instance/role) — this module never accepts or stores secrets. A single Session is
reused; clients are cached per (service, region) so repeated tool calls are cheap.
"""

from __future__ import annotations

import os
import threading
from functools import lru_cache

import boto3


class Aws:
    """A thin, cached wrapper over a boto3 Session.

    One instance is shared across tool calls (see `default()`). Clients are memoised
    per (service, region); the wrapped Session's default region is used when a call
    doesn't override it.
    """

    def __init__(self, region: str | None = None, profile: str | None = None):
        self._session = boto3.Session(
            region_name=region or _region_from_env(),
            profile_name=profile or os.environ.get("AWS_PROFILE") or None,
        )
        self._clients: dict[tuple[str, str | None], object] = {}
        self._lock = threading.Lock()

    @property
    def session(self) -> boto3.Session:
        return self._session

    @property
    def region(self) -> str | None:
        return self._session.region_name

    def client(self, service: str, region: str | None = None):
        key = (service, region)
        with self._lock:
            cached = self._clients.get(key)
            if cached is None:
                cached = self._session.client(service, region_name=region)
                self._clients[key] = cached
            return cached

    def account_id(self) -> str:
        return self.client("sts").get_caller_identity()["Account"]


def _region_from_env() -> str | None:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")


def resolve_region(explicit: str | None, aws: "Aws | None" = None) -> str | None:
    """Region precedence: explicit arg -> AWS_REGION/AWS_DEFAULT_REGION -> session default."""
    if explicit:
        return explicit
    env = _region_from_env()
    if env:
        return env
    return aws.region if aws else boto3.Session().region_name


@lru_cache(maxsize=1)
def default() -> Aws:
    """Process-wide default Aws wrapper, built from the ambient environment."""
    return Aws()


def for_region(region: str | None) -> Aws:
    """An Aws wrapper pinned to a specific region (falls back to the default's region)."""
    base = default()
    if region is None or region == base.region:
        return base
    return Aws(region=region, profile=os.environ.get("AWS_PROFILE"))
