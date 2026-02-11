# SPDX-License-Identifier: AGPL-3.0-or-later
"""Spell-check plugin — detects likely typos via Google autocomplete and
transparently corrects the search query, displaying a Google-style
"Showing results for … / Search exactly for …" banner."""

import logging
import typing as t

import flask

from searx.autocomplete import search_autocomplete
from searx.plugins import Plugin, PluginInfo

if t.TYPE_CHECKING:
    from searx.plugins import PluginCfg
    from searx.search import SearchWithPlugins
    from searx.plugins._core import SXNG_Request

log = logging.getLogger(__name__)

def _levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein edit-distance."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _normalise(s: str) -> str:
    """Lower-case and collapse whitespace."""
    return " ".join(s.lower().split())


def _looks_like_typo(original: str, suggestion: str) -> bool:
    """Return True when *suggestion* seems like a spell-fixed version of
    *original* (similar but not identical)."""
    a, b = _normalise(original), _normalise(suggestion)
    if a == b:
        return False
    # Only consider corrections where the words are close
    dist = _levenshtein(a, b)
    # Allow edits proportional to query length but cap at 3
    max_dist = min(3, max(1, len(a) // 4))
    return dist <= max_dist

@t.final
class SXNGPlugin(Plugin):
    """Auto-corrects likely typos and shows a Google-style correction banner."""

    id = "spell_check"

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.info = PluginInfo(
            id=self.id,
            name="Spell Check",
            description="Detects typos and shows corrected results with a banner.",
            preference_section="general",
        )

    def pre_search(self, request: "SXNG_Request", search: "SearchWithPlugins") -> bool:
        query = search.search_query.query.strip()
        if not query or len(query) < 3:
            return True

        # Skip if the user explicitly asked for this exact query (via the
        # "Search exactly" link which adds &spell=off)
        if flask.request.args.get("spell") == "off":
            return True

        # Skip if content filter blocked this query
        if getattr(flask.g, "content_blocked", False):
            return True

        try:
            suggestions = search_autocomplete("brave", query, "en")
        except Exception:
            log.debug("Spell-check autocomplete failed for %r", query)
            return True

        if not suggestions:
            return True

        best = suggestions[0]
        if _looks_like_typo(query, best):
            flask.g.spell_original = query
            flask.g.spell_corrected = best
            search.search_query.query = best
            log.info("Spell-check: %r → %r", query, best)

        return True
