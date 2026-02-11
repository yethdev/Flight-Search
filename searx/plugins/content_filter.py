# SPDX-License-Identifier: AGPL-3.0-or-later
"""Content filter plugin — blocks searches for dangerous, illegal, or
age-inappropriate content and shows a kid-friendly warning with
relevant helpline numbers when applicable."""

import logging
import re
import typing as t

import flask
from searx.plugins import Plugin, PluginInfo
from searx.result_types.answer import Answer

if t.TYPE_CHECKING:
    from searx.plugins import PluginCfg
    from searx.search import SearchWithPlugins
    from searx.plugins._core import SXNG_Request

log = logging.getLogger(__name__)

_CATEGORIES: dict[str, dict] = {
    "weapons": {
        "terms": [
            "gun", "guns", "firearm", "firearms", "rifle", "rifles",
            "shotgun", "shotguns", "pistol", "pistols", "revolver",
            "handgun", "handguns", "ammo", "ammunition", "ar-15", "ar15",
            "ak-47", "ak47", "assault rifle", "assault weapon",
            "sniper rifle", "machine gun", "submachine gun", "uzi",
            "glock", "buy gun", "buy guns", "gun shop", "gun store",
            "gun broker", "gunbroker", "gunshop", "gunsho",
            "weapon", "weapons", "semi-automatic", "semiautomatic",
            "concealed carry", "gun dealer", "gun sale",
            "silencer", "suppressor", "bump stock",
        ],
        "message": "This search has been blocked because it may contain content that isn't appropriate for young users.",
    },
    "explosives": {
        "terms": [
            "bomb", "bombs", "how to make a bomb", "pipe bomb",
            "explosive", "explosives", "dynamite", "c4 explosive",
            "grenade", "grenades", "molotov cocktail", "detonator",
            "how to make explosives", "improvised explosive",
            "ied", "incendiary",
        ],
        "message": "This search has been blocked because it involves dangerous content.",
    },
    "drugs": {
        "terms": [
            "cocaine", "heroin", "methamphetamine", "meth",
            "crystal meth", "crack cocaine", "fentanyl", "opium",
            "lsd", "ecstasy", "mdma", "ketamine",
            "pcp", "angel dust", "shrooms", "magic mushrooms",
            "psilocybin", "dmt", "ayahuasca", "ghb",
            "buy drugs", "drug dealer", "drug market",
            "darknet market", "silk road", "how to make meth",
            "how to make drugs", "how to cook meth",
            "marijuana", "weed", "cannabis", "thc", "edibles",
            "vape", "vaping", "juul", "e-cigarette",
            "oxycontin", "oxycodone", "xanax", "percocet",
            "adderall", "codeine", "lean", "purple drank",
            "whippets", "nitrous oxide", "inhalants",
            "bath salts", "spice drug", "synthetic cannabinoid",
            "amphetamine", "barbiturate", "benzodiazepine",
        ],
        "message": "This search has been blocked because it involves drugs or controlled substances.",
        "hotline": "If you or someone you know is struggling with substance use, contact the SAMHSA National Helpline: 1-800-662-4357 (free, confidential, 24/7).",
    },
    "self_harm": {
        "terms": [
            "how to kill myself", "how to commit suicide",
            "suicide methods", "ways to die", "i want to die",
            "kill myself", "end my life", "painless death",
            "self harm", "self-harm", "cutting myself",
            "how to cut yourself", "how to hurt myself",
            "overdose", "how to overdose",
            "suicidal", "suicide", "hang myself",
            "jump off a bridge", "slit wrists",
            "want to kill myself", "no reason to live",
            "better off dead", "how to disappear",
            "pro ana", "pro mia", "thinspo", "thinspiration",
            "eating disorder tips",
        ],
        "message": "It looks like you or someone you know might be going through a tough time. You are not alone, and there are people who care and want to help.",
        "hotline": "988 Suicide & Crisis Lifeline: Call or text 988 (available 24/7). Crisis Text Line: Text HOME to 741741.",
    },
    "adult_content": {
        "terms": [
            "porn", "porno", "pornography", "pornhub", "xvideos",
            "xnxx", "onlyfans", "chaturbate", "brazzers",
            "hentai", "rule34", "rule 34", "xxx", "nsfw",
            "nude", "nudes", "naked", "sex video", "sex tape",
            "erotic", "erotica", "playboy", "penthouse",
            "escort", "escorts", "escort service",
            "strip club", "stripper", "strippers",
            "hookup", "hook up site", "booty call",
            "milf", "dilf", "bdsm", "fetish",
            "camgirl", "cam girl", "webcam girl",
            "adult video", "adult content", "adult site",
            "nude pics", "leaked nudes",
            "sexting", "sext",
        ],
        "message": "This search has been blocked because it may contain adult content that isn't appropriate for young users.",
    },
    "violence_gore": {
        "terms": [
            "gore", "beheading", "execution video",
            "murder video", "death video", "snuff",
            "torture video", "cartel video", "cartel execution",
            "liveleak death", "bestgore", "faces of death",
            "how to kill someone", "how to murder",
            "how to poison someone", "how to stab",
            "how to strangle", "hit man", "hitman for hire",
            "hire assassin", "serial killer methods",
        ],
        "message": "This search has been blocked because it involves violent or disturbing content.",
    },
    "gambling": {
        "terms": [
            "online casino", "online gambling", "sports betting",
            "bet online", "poker online", "slot machine",
            "draftkings", "fanduel", "bovada", "betway",
            "online slots", "roulette online", "blackjack online",
            "csgo gambling", "skin gambling", "crypto casino",
        ],
        "message": "This search has been blocked because it involves gambling content that isn't appropriate for young users.",
    },
    "illegal_activities": {
        "terms": [
            "how to hack", "hacking tutorial", "ddos attack",
            "how to ddos", "phishing kit", "carding",
            "credit card fraud", "identity theft how to",
            "how to steal", "how to shoplift", "shoplifting tips",
            "fake id", "fake identity", "counterfeit money",
            "how to pick a lock", "how to break in",
            "how to hotwire", "how to hotwire a car",
            "dark web", "darkweb", "tor hidden services",
            "darknet", "how to access dark web",
            "swatting", "how to swat",
        ],
        "message": "This search has been blocked because it involves potentially illegal activities.",
    },
    "hate_speech": {
        "terms": [
            "white supremacy", "white supremacist", "neo nazi",
            "nazi propaganda", "kkk", "ku klux klan",
            "racial slur", "hate group",
        ],
        "message": "This search has been blocked because it may involve hateful content.",
    },
    "tobacco_alcohol": {
        "terms": [
            "buy cigarettes", "buy tobacco", "buy alcohol",
            "buy beer online", "buy liquor online", "buy vape",
            "juul pods", "vape juice",
        ],
        "message": "This search has been blocked because it involves products that aren't appropriate for young users.",
    },
    "proxies": {
        "terms": [
            # Specific proxy / unblocker tool names
            "croxyproxy", "croxy proxy", "croxy",
            "anuraos", "anura os", "anura proxy",
            "petezah", "petezah proxy",
            "frogies arcade", "frogies",
            # Proxy-seeking phrases (won't match "proxy war", "proxy vote", etc.)
            "web proxy", "free proxy", "proxy site", "proxy sites",
            "proxy browser", "proxy server free", "proxy unblock",
            "unblock proxy", "unblock sites", "unblock websites",
            "unblocker", "site unblocker", "school unblocker",
            "bypass filter", "bypass school filter", "bypass firewall",
            "bypass blocker", "bypass web filter",
            "unblocked games", "unblocked sites", "unblock", "unblocker", "unblocked",
            "proxy list", "proxy download",
            "quasar proxy", "quasar browser", "quasar unblocker",
        ],
        # Also match common misspellings / leet-speak of "proxy" as standalone
        "patterns": [
            r"(?:^|\s)pr[0]xy(?:\s|$)",                  # pr0xy (leet-speak)
            r"(?:^|\s)prox[iIeE]e?(?:\s|$)",             # proxie, proxi
            r"(?:^|\s)prx?oy(?:\s|$)",                    # prxoy, proy
            r"(?:^|\s)porxy(?:\s|$)",                      # porxy
            r"^proxy$",                                    # exact standalone "proxy"
        ],
        "message": "This search has been blocked because it involves proxy or filter circumvention tools that aren't allowed.",
    },
}

_BLOCK_RULES: list[tuple[re.Pattern, str, str]] = []


def _compile_rules():
    for cat, entry in _CATEGORIES.items():
        message = entry["message"]
        hotline = entry.get("hotline", "")
        for term in entry["terms"]:
            # Escape regex chars, match as whole word (word-boundary)
            escaped = re.escape(term)
            pattern = re.compile(
                r"(?:^|[\s\-_/,;.!?\"'])"
                + escaped
                + r"(?:[\s\-_/,;.!?\"']|$|s|es|ing|ed)",
                re.IGNORECASE,
            )
            _BLOCK_RULES.append((pattern, message, hotline))
        # Extra raw regex patterns (for fuzzy / leet-speak matching)
        for raw_pat in data.get("patterns", []):
            pattern = re.compile(raw_pat, re.IGNORECASE)
            _BLOCK_RULES.append((pattern, message, hotline))


_compile_rules()


@t.final
class SXNGPlugin(Plugin):
    """Blocks searches for inappropriate, dangerous, or illegal content."""

    id = "content_filter"

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.info = PluginInfo(
            id=self.id,
            name="Content Filter",
            description="Blocks searches for dangerous, illegal, or age-inappropriate content.",
            preference_section="general",
        )

    def pre_search(self, request: "SXNG_Request", search: "SearchWithPlugins") -> bool:
        query = search.search_query.query.strip().lower()
        if not query:
            return True

        for pattern, message, hotline in _BLOCK_RULES:
            if pattern.search(query):
                # Stash the warning on the request so post_search can pick it up
                request.blocked_message = message  # type: ignore[attr-defined]
                request.blocked_hotline = hotline  # type: ignore[attr-defined]
                flask.g.content_blocked = True
                log.info("Content filter blocked query: %r", query)
                return False  # stop the search

        return True

    # noinspection PyMethodMayBeStatic
    def on_result(self, request: "SXNG_Request", search: "SearchWithPlugins", result: dict) -> bool:
        """Check each individual result's title, URL, and snippet against the
        block-list.  Return ``False`` to suppress the result."""
        text_parts: list[str] = []
        for key in ("title", "url", "content", "parsed_url", "img_src", "thumbnail"):
            field_value = result.get(key)
            if field_value:
                text_parts.append(str(field_value).lower())
        searchable = " ".join(text_parts)
        if not searchable:
            return True
        for pattern, _message, _hotline in _BLOCK_RULES:
            if pattern.search(searchable):
                log.info("Content filter suppressed result: %s", result.get("url", "?"))
                return False
        return True

    def post_search(self, request: "SXNG_Request", search: "SearchWithPlugins"):
        message = getattr(request, "blocked_message", None)
        if not message:
            return []

        hotline = getattr(request, "blocked_hotline", "")
        full_text = message
        if hotline:
            full_text += " " + hotline

        return [Answer(answer=full_text)]
