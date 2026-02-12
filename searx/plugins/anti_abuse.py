# SPDX-License-Identifier: AGPL-3.0-or-later
"""Anti-abuse plugin — rate-limits search and autocomplete endpoints per IP
to prevent automated scraping, API abuse, and excessive usage."""

import logging
import time
import typing as t
from collections import defaultdict

import flask

from searx.plugins import Plugin, PluginInfo

if t.TYPE_CHECKING:
    from searx.plugins import PluginCfg
    from searx.search import SearchWithPlugins
    from searx.plugins._core import SXNG_Request

log = logging.getLogger(__name__)

_SEARCH_LIMIT = 30
_SEARCH_WINDOW = 60

_AC_LIMIT = 60
_AC_WINDOW = 60

# catches scripted abuse that spreads across endpoints
_GLOBAL_LIMIT = 120
_GLOBAL_WINDOW = 60

_search_buckets: dict[str, list[float]] = defaultdict(list)
_ac_buckets: dict[str, list[float]] = defaultdict(list)
_global_buckets: dict[str, list[float]] = defaultdict(list)


def _check_limit(buckets: dict[str, list[float]], ip: str, limit: int, window: float) -> bool:
    now = time.monotonic()
    bucket = buckets[ip]
    cutoff = now - window
    buckets[ip] = bucket = [ts for ts in bucket if ts > cutoff]
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


def _get_ip() -> str:
    return (
        flask.request.headers.get("CF-Connecting-IP")
        or flask.request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or flask.request.remote_addr
        or "unknown"
    )


@t.final
class SXNGPlugin(Plugin):
    """Rate-limits search, autocomplete, and JSON API endpoints."""

    id = "anti_abuse"

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.info = PluginInfo(
            id=self.id,
            name="Anti-Abuse",
            description="Rate-limits endpoints to prevent scraping and API abuse.",
            preference_section="general",
        )

    def init(self, app: flask.Flask) -> bool:
        @app.before_request
        def _rate_limit_check():
            ip = _get_ip()
            path = flask.request.path

            # Global rate limit
            if _check_limit(_global_buckets, ip, _GLOBAL_LIMIT, _GLOBAL_WINDOW):
                log.warning("Global rate limit hit for %s on %s", ip, path)
                return flask.Response(
                    "Rate limit exceeded. Please slow down.",
                    status=429,
                    content_type="text/plain",
                )

            # Search endpoint rate limit
            if path == "/search":
                if _check_limit(_search_buckets, ip, _SEARCH_LIMIT, _SEARCH_WINDOW):
                    log.warning("Search rate limit hit for %s", ip)
                    return flask.Response(
                        "Too many searches. Please wait a moment.",
                        status=429,
                        content_type="text/plain",
                    )

            # Autocomplete endpoint rate limit
            elif path == "/autocompleter":
                if _check_limit(_ac_buckets, ip, _AC_LIMIT, _AC_WINDOW):
                    return flask.Response(
                        "[]",
                        status=429,
                        content_type="application/json",
                    )

            # Block JSON/RSS API output formats entirely for non-html consumers
            # (prevents automated scraping via ?format=json)
            fmt = flask.request.args.get("format", "")
            if fmt in ("json", "csv", "rss") and path == "/search":
                # Only allow if request appears to come from the instance itself
                referer = flask.request.headers.get("Referer", "")
                if not referer or not any(
                    h in referer for h in (
                        "localhost", "127.0.0.1",
                        "search.yeth.dev",
                        "search.yeth.uk", "search.software-resources.org",
                        "flightsearch.kids",
                    )
                ):
                    log.info("Blocked external API access from %s (format=%s)", ip, fmt)
                    return flask.Response(
                        "API access is not available on this instance.",
                        status=403,
                        content_type="text/plain",
                    )

        log.info("Anti-abuse rate limiter registered")
        return True
