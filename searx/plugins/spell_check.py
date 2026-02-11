# SPDX-License-Identifier: AGPL-3.0-or-later
"""Spell-check plugin — detects likely typos via Brave autocomplete and
transparently corrects the search query, showing a Google-style
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


def _norm(s: str) -> str:
    return " ".join(s.lower().split())


def _try_word_correction(original: str, suggestions: list[str]) -> str | None:
    """Attempt word-level correction: only corrects when exactly one word
    differs and multiple suggestions agree on the replacement."""
    orig_words = _norm(original).split()
    if not orig_words:
        return None

    votes: dict[int, dict[str, int]] = {}

    for suggestion in suggestions:
        sug_words = _norm(suggestion).split()
        if len(sug_words) != len(orig_words):
            continue
        for i, (ow, sw) in enumerate(zip(orig_words, sug_words)):
            if ow != sw:
                if i not in votes:
                    votes[i] = {}
                votes[i][sw] = votes[i].get(sw, 0) + 1

    if len(votes) != 1:
        return None

    pos, candidates = next(iter(votes.items()))
    orig_word = orig_words[pos]
    best_replacement = max(candidates, key=candidates.get)
    vote_count = candidates[best_replacement]

    if vote_count < 2:
        return None

    dist = _levenshtein(orig_word, best_replacement)
    max_allowed = min(2, max(1, len(orig_word) // 4))
    if dist > max_allowed:
        return None

    corrected_words = original.split()
    if pos < len(corrected_words):
        corrected_words[pos] = best_replacement
    return " ".join(corrected_words)


@t.final
class SXNGPlugin(Plugin):
    """Auto-corrects likely typos and shows a correction banner."""

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

        if flask.request.args.get("spell") == "off":
            return True

        if getattr(flask.g, "content_blocked", False):
            return True

        try:
            suggestions = search_autocomplete("brave", query, "en")
        except Exception:
            log.debug("Spell-check autocomplete failed for %r", query)
            return True

        if not suggestions:
            return True

        norm_query = _norm(query)
        for sug in suggestions:
            if _norm(sug) == norm_query:
                return True

        correction = _try_word_correction(query, suggestions)
        if correction and _norm(correction) != norm_query:
            flask.g.spell_original = query
            flask.g.spell_corrected = correction
            search.search_query.query = correction
            log.info("Spell-check: %r → %r", query, correction)

        return True
