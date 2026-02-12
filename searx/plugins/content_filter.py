# SPDX-License-Identifier: AGPL-3.0-or-later
"""Content filter - risk-scored, context-aware blocking with dynamic
domain blocklists and per-category guidance for a kid-safe search engine."""

import logging
import re
import threading
import typing as t
import urllib.request
from concurrent.futures import ThreadPoolExecutor

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
            "gun broker", "gunbroker", "gunshop",
            "weapon", "weapons", "semi-automatic", "semiautomatic",
            "concealed carry", "gun dealer", "gun sale",
            "silencer", "suppressor", "bump stock",
        ],
        "risk": 90, "reducible": False, "label": "weapons",
        "message": "This search was blocked because it relates to: weapons.",
    },
    "explosives": {
        "terms": [
            "bomb", "bombs", "how to make a bomb", "pipe bomb",
            "explosive", "explosives", "dynamite", "c4 explosive",
            "grenade", "grenades", "molotov cocktail", "detonator",
            "how to make explosives", "improvised explosive",
            "ied", "incendiary",
        ],
        "risk": 95, "reducible": False, "label": "explosives",
        "message": "This search was blocked because it relates to: dangerous materials.",
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
        "risk": 90, "reducible": False, "label": "drugs",
        "message": "This search was blocked because it relates to: drugs or controlled substances.",
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
        "risk": 95, "reducible": False, "label": "self-harm",
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
            "sexy", "sexiest", "sexier", "sexi",
            "masturbation", "masturbate", "masturbating",
            "blow job", "blowjob", "blowjobs",
            "handjob", "hand job",
            "jack off", "jacking off", "jerk off", "jerking off",
            "wank", "wanking",
            "pussy", "pussies", "vagina",
            "boob", "boobs", "tits", "titties", "breasts",
            "dick pic", "dick pics",
            "hickey", "hickeys", "love bite",
            "oral sex", "anal sex",
            "cum", "cumming", "cumshot",
            "threesome", "threesomes",
            "orgasm", "orgasms",
            "nipple", "nipples", "nip slip",
            "vibrator", "dildo", "sex toy", "sex toys",
            "lingerie",
            "striptease", "lap dance",
            "fingering",
            "topless", "shirtless",
            "twerk", "twerking",
            "foreplay",
            "one night stand",
            "friends with benefits",
            "sugar daddy", "sugar mommy",
            "dominatrix",
            "kinky", "kink",
            "smut", "smutty",
            "lewd",
            "ahegao",
            "doujinshi", "doujin",
            "fap", "fapping",
            "deepfake",
            "cleavage",
            "thong", "g-string",
            "pegging",
            "rimjob", "rim job",
            "sex position", "sex positions",
            "kamasutra", "kama sutra",
            "penis", "genitals", "genitalia",
            "pubic",
            "sex ed", "sex education",
            "how babies are made", "how are babies made",
            "where do babies come from",
            "r34", "r 34",
            "yaoi", "yuri",
            "furry porn", "furry nsfw",
            "rule 63",
            "hot girls", "hot guys", "hot women", "hot men",
            "bikini", "bikini pics",
            "upskirt", "downblouse",
            "camel toe", "cameltoe",
            "bulge",
            "make out", "making out",
            "grind", "grinding",
            "horny", "aroused", "arousal", "turned on",
            "puberty photos", "puberty pictures", "puberty pics",
        ],
        "patterns": [
            r"(?:what|how)\s+(?:do|does|did|would|should)\s+(?:boyfriend|girlfriend|couple|partner|husband|wife|boy\s*friend|girl\s*friend)s?(?:\s+and\s+(?:boyfriend|girlfriend|couple|partner|husband|wife)s?)?\s+(?:do|like|try)\s+(?:together|alone|in\s+bed|at\s+night|when\s+alone|in\s+private)",
            r"(?:boyfriend|girlfriend|couple|partner|husband|wife)s?(?:\s+and\s+(?:boyfriend|girlfriend|partner)s?)?\s+.{0,20}(?:together|alone|in\s+bed|at\s+night|when\s+alone|in\s+private)",
            r"(?:picture|photo|pic|image|video)s?\s+(?:of\s+)?(?:people|women|men|girl|boy|teen|person|bodie)s?\s+(?:with\s+)?(?:no\s+(?:shirt|clothes|clothing|top)|naked|nude|topless|shirtless|undress|without\s+(?:shirt|clothes|clothing))",
            r"(?:how|where)\s+(?:are\s+)?(?:babies?|children|kids?)\s+(?:are\s+)?(?:really\s+)?(?:actually\s+)?(?:made|come\s+from|born|conceived|created)",
            r"\b(?:babies?|children|kids?)\s+.{0,15}(?:made|come\s+from|conceived|created)\b",
            r"sexy\s+(?:yoga|dance|outfit|pose|costume|photo|pic|picture|video|move|position)s?",
            r"(?:what\s+does?\s+)?(?:sexy|sexi)\s+mean",
            r"(?:change|changing)s?\s+(?:in\s+)?(?:body|bodies)\s+(?:during|for|in)\s+puberty\b.*?(?:photo|pic|picture|image)s?",
            r"\bpuberty\b.{0,30}(?:photo|pic|picture|image)s?\b",
            r"(?:where|how|why)\s+(?:do|does|are)\s+(?:girl|boy|women|men|teen)s?\s+(?:have|get|grow)\s+(?:breast|boob|tit|chest)s?",
            r"(?:blow\s*job|hand\s*job|rim\s*job)\s+(?:tip|trick|technique|instruction|tutorial|how|guide)s?",
            r"(?:jack|jerk|wank)(?:ing)?\s+off\s+(?:instruction|tutorial|how|tip|guide)s?",
            r"(?:sex|sexual)\s+(?:education|ed)\s+(?:cartoon|video|animation|show|episode)s?",
            r"(?:what\s+is\s+(?:a\s+)?)?(?:hickey|love\s+bite|making\s+out|french\s+kiss)(?:\s+and\s+how)?",
            r"(?:what\s+is\s+(?:a\s+)?)?(?:masturbation|blow\s*job|hand\s*job|orgasm|foreplay|oral\s+sex)\s+(?:for|explained|mean|definition)",
            r"(?:what\s+is\s+(?:a\s+)?)?(?:pussy|dick|cock|penis|vagina|boob|tit|breast)\b",
            r"(?:how\s+to|ways?\s+to|best\s+way\s+to)\s+(?:give|get|make|do)\s+(?:a\s+)?(?:hickey|love\s+bite|blow\s*job|hand\s*job)",
            r"\b(?:no\s+shirt|shirtless|topless|braless)\s+(?:at|on|in)\s+(?:the\s+)?(?:beach|pool|gym|park)",
        ],
        "risk": 90, "reducible": False, "label": "adult content",
        "message": "This search was blocked because it relates to: adult content.",
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
        "risk": 90, "reducible": False, "label": "violence",
        "message": "This search was blocked because it relates to: violence.",
    },
    "gambling": {
        "terms": [
            "online casino", "online gambling", "sports betting",
            "bet online", "poker online", "slot machine",
            "draftkings", "fanduel", "bovada", "betway",
            "online slots", "roulette online", "blackjack online",
            "csgo gambling", "skin gambling", "crypto casino",
        ],
        "risk": 85, "reducible": False, "label": "gambling",
        "message": "This search was blocked because it relates to: gambling.",
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
        "risk": 90, "reducible": False, "label": "illegal activity",
        "message": "This search was blocked because it relates to: illegal activities.",
    },
    "hate_speech": {
        "terms": [
            "white supremacy", "white supremacist", "neo nazi",
            "nazi propaganda", "kkk", "ku klux klan",
            "racial slur", "hate group",
        ],
        "risk": 90, "reducible": False, "label": "hate speech",
        "message": "This search was blocked because it relates to: hateful content.",
    },
    "tobacco_alcohol": {
        "terms": [
            "buy cigarettes", "buy tobacco", "buy alcohol",
            "buy beer online", "buy liquor online", "buy vape",
            "juul pods", "vape juice",
        ],
        "risk": 85, "reducible": False, "label": "tobacco or alcohol",
        "message": "This search was blocked because it relates to: age-restricted products.",
    },
    "proxies": {
        "terms": [
            "croxyproxy", "croxy proxy", "croxy",
            "anuraos", "anura os", "anura proxy",
            "petezah", "petezah proxy",
            "frogies arcade", "frogies",
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
        "patterns": [
            r"(?:^|\s)pr[0]xy(?:\s|$)",
            r"(?:^|\s)prox[iIeE]e?(?:\s|$)",
            r"(?:^|\s)prx?oy(?:\s|$)",
            r"(?:^|\s)porxy(?:\s|$)",
            r"^proxy$",
        ],
        "risk": 80, "reducible": False, "label": "filter circumvention",
        "message": "This search was blocked because it relates to: proxy or filter circumvention tools.",
    },
    "domestic_violence": {
        "terms": [
            "domestic violence", "domestic abuse",
            "abusive relationship", "abusive partner",
            "my partner hits me", "my husband hits me", "my wife hits me",
            "my boyfriend hits me", "my girlfriend hits me",
            "abuse at home", "being abused at home",
            "he hits me", "she hits me",
            "scared of my partner", "controlling relationship",
            "intimate partner violence",
        ],
        "risk": 90, "reducible": True, "label": "domestic violence",
        "message": "If you or someone you know is in a dangerous situation, help is available right now.",
        "hotline": "National Domestic Violence Hotline: 1-800-799-7233 (24/7, free, confidential). If you are in immediate danger, call 911.",
    },
    "sexual_assault": {
        "terms": [
            "sexual assault", "sexually assaulted",
            "rape", "raped", "molested", "molestation",
            "touched inappropriately", "someone touched me",
            "sexual abuse", "sexually abused",
            "groped", "groping",
            "date rape", "statutory rape",
        ],
        "risk": 95, "reducible": False, "label": "sexual assault",
        "message": "If you or someone you know has been affected, confidential help is available.",
        "hotline": "RAINN National Sexual Assault Hotline: 1-800-656-4673 (24/7, free, confidential). If you are in immediate danger, call 911.",
    },
    "child_abuse": {
        "terms": [
            "child abuse", "child molest", "child molestation",
            "my parents hurt me", "my dad hits me", "my mom hits me",
            "being abused", "someone is hurting me",
            "adults touching kids", "inappropriate touching",
            "child trafficking", "child exploitation",
            "child pornography", "csam",
        ],
        "risk": 100, "reducible": False, "label": "child safety",
        "message": "If you or someone you know is being hurt, please reach out for help right now.",
        "hotline": "Childhelp National Child Abuse Hotline: 1-800-422-4453 (24/7). If you are in immediate danger, call 911.",
    },
    "emergency": {
        "terms": [
            "i need help now", "someone is trying to hurt me",
            "i'm in danger", "im in danger",
            "call the police for me", "i need the police",
            "emergency help", "please help me",
            "i don't feel safe", "i dont feel safe",
            "someone is following me",
        ],
        "risk": 100, "reducible": False, "label": "emergency",
        "message": "If you are in danger or need emergency help:",
        "hotline": "Call 911 (or your local emergency number) immediately. 988 Suicide & Crisis Lifeline: Call or text 988. Crisis Text Line: Text HOME to 741741.",
    },
    "gaming_distraction": {
        "terms": [
            "unblocked games", "unblocked game", "games unblocked",
            "school games", "games for school", "games at school",
            "classroom games", "play at school", "play in school",
            "games not blocked", "not blocked games",
            "games that aren't blocked", "games that are not blocked",
            "cool math games", "coolmath", "cool math",
            "poki", "kizi", "y8", "miniclip", "armor games",
            "crazy games", "crazygames",
            "io games", "slither.io", "agar.io", "krunker.io",
            "1v1.lol", "shell shockers", "slope game", "slope unblocked",
            "retro bowl", "retro bowl unblocked",
            "fnf unblocked", "friday night funkin unblocked",
            "run 3 unblocked", "happy wheels unblocked",
            "subway surfers unblocked", "among us unblocked",
            "minecraft unblocked", "roblox unblocked",
            "fortnite unblocked", "geometry dash unblocked",
            "snake game", "google snake", "dinosaur game",
            "game sites", "gaming sites", "free game sites",
            "flash games", "browser games",
            "tyrone unblocked", "tyrone's unblocked",
            "ubg365", "ubg100", "ubg77",
            "66ez", "76 unblocked", "77 unblocked",
            "scratch games", "html5 games",
        ],
        "patterns": [
            r"\bunblocked\b.{0,20}\bgames?\b",
            r"\bgames?\b.{0,20}\bunblocked\b",
            r"\b(?:play|game|gaming)\b.{0,15}\b(?:school|class|blocked)\b",
        ],
        "risk": 65, "reducible": True, "label": "gaming distraction",
        "message": "Some results were filtered because they relate to: gaming or distraction sites.",
    },
    "social_media": {
        "terms": [
            "tiktok unblocked", "instagram unblocked",
            "snapchat unblocked", "discord unblocked",
            "twitter unblocked", "facebook unblocked",
            "youtube unblocked", "reddit unblocked",
            "snapchat web", "tiktok web",
            "social media at school", "access social media",
            "unblocked social media", "social media unblocked",
        ],
        "patterns": [
            r"\b(?:tiktok|snapchat|instagram|discord|twitter|facebook|youtube|reddit)\b.{0,15}\bunblocked\b",
            r"\bunblocked\b.{0,15}\b(?:tiktok|snapchat|instagram|discord|twitter|facebook|youtube|reddit)\b",
        ],
        "risk": 60, "reducible": True, "label": "social media bypass",
        "message": "Some results were filtered because they relate to: social media bypass tools.",
    },
    "cheating_academic": {
        "terms": [
            "buy essay", "buy essays", "essay writing service",
            "pay someone to write", "do my homework",
            "homework answers", "test answers",
            "cheat on test", "cheat on exam",
            "cheating methods", "how to cheat on a test",
            "answer key", "exam answers",
            "coursehero", "course hero", "chegg answers",
            "photomath answers", "brainly answers",
            "copy homework", "plagiarism tool",
            "essay mill", "paper mill", "ghost writer academic",
            "write my paper", "write my essay",
            "take my exam", "take my test",
        ],
        "risk": 55, "reducible": True, "label": "academic dishonesty",
        "message": "Some results were filtered because they relate to: academic dishonesty.",
    },
    "piracy": {
        "terms": [
            "free movies online", "watch movies free",
            "free streaming", "123movies", "putlocker",
            "fmovies", "soap2day", "solarmovie", "yesmovies",
            "123 movies", "movie streaming free",
            "watch free online", "free tv shows online",
            "pirate bay", "thepiratebay", "torrent download",
            "torrent site", "torrent sites", "kickass torrents",
            "rarbg", "1337x", "yts", "eztv",
            "free music download", "mp3 download free",
            "free ebook download", "libgen", "z-library",
            "cracked software", "cracked games",
            "free download full version", "keygen",
            "serial key", "activation crack",
            "watch anime free", "free anime streaming",
            "gogoanime", "9anime", "kissanime",
        ],
        "risk": 60, "reducible": False, "label": "piracy",
        "message": "Some results were filtered because they relate to: piracy or copyright infringement.",
    },
    "vpn_circumvention": {
        "terms": [
            "free vpn", "vpn for school", "vpn unblocked",
            "school vpn", "vpn to bypass", "vpn bypass",
            "vpn chrome extension", "vpn extension free",
            "hide browsing", "hide search history",
            "anonymous browsing", "private browsing bypass",
            "tor browser download", "tor download",
            "dns bypass", "dns over https bypass",
            "change dns school", "dns changer",
        ],
        "risk": 60, "reducible": True, "label": "filter circumvention",
        "message": "Some results were filtered because they relate to: network filter circumvention.",
    },
}

_EDUCATIONAL_PREFIXES: list[re.Pattern] = [
    re.compile(r"^(?:history|origins?|evolution|timeline)\s+(?:of|behind)\b", re.I),
    re.compile(r"^what\s+(?:is|are|was|were)\b", re.I),
    re.compile(r"^(?:effects?|impact|consequences?|dangers?)\s+of\b", re.I),
    re.compile(r"^(?:science|chemistry|physics|biology)\s+(?:of|behind)\b", re.I),
    re.compile(r"^how\s+does?\s+\w+\s+work\b", re.I),
    re.compile(r"^why\s+(?:is|are|do|does|did|was|were)\b", re.I),
    re.compile(r"\b(?:for\s+kids|for\s+students|for\s+school|homework|essay|report|project)\b", re.I),
    re.compile(r"\b(?:definition|meaning|explained|overview|summary)\b", re.I),
]

_EDUCATIONAL_SCORE_REDUCTION = 30
_NEVER_REDUCE = frozenset({
    "self_harm", "adult_content", "sexual_assault", "child_abuse",
    "proxies", "illegal_activities", "emergency",
})


def _has_educational_context(query: str) -> bool:
    for pat in _EDUCATIONAL_PREFIXES:
        if pat.search(query):
            return True
    return False


_BLOCK_RULES: list[tuple[re.Pattern, int, str, str, str, str]] = []


def _compile_rules():
    for cat, entry in _CATEGORIES.items():
        risk = entry["risk"]
        label = entry["label"]
        message = entry["message"]
        hotline = entry.get("hotline", "")
        for term in entry["terms"]:
            escaped = re.escape(term)
            pat = re.compile(
                r"(?:^|[\s\-_/,;.!?\"'])" + escaped + r"(?:[\s\-_/,;.!?\"']|$|s|es|ing|ed)",
                re.IGNORECASE,
            )
            _BLOCK_RULES.append((pat, risk, label, message, hotline, cat))
        for raw_pat in entry.get("patterns", []):
            pat = re.compile(raw_pat, re.IGNORECASE)
            _BLOCK_RULES.append((pat, risk, label, message, hotline, cat))


_compile_rules()

_BLOCKLIST_URLS: list[str] = [
    "https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/redirect-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt",
    "https://blocklistproject.github.io/Lists/alt-version/vaping-nl.txt",
]

_blocked_domains: set[str] = set()
_blocklist_ready = threading.Event()


def _fetch_single_list(url: str) -> set[str]:
    domains: set[str] = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Flight-Search/1.0"})
        with urllib.request.urlopen(req, timeout=45) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="ignore").strip().lower()
                if line and not line.startswith("#") and not line.startswith("!"):
                    domains.add(line)
    except Exception:
        log.warning("Failed to fetch blocklist: %s", url)
    return domains


def _load_all_blocklists():
    global _blocked_domains
    merged: set[str] = set()
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_fetch_single_list, u): u for u in _BLOCKLIST_URLS}
        for future in futures:
            merged.update(future.result())
    _blocked_domains = merged
    _blocklist_ready.set()
    log.info("Loaded %d blocked domains from %d blocklists", len(merged), len(_BLOCKLIST_URLS))


threading.Thread(target=_load_all_blocklists, daemon=True, name="blocklist-loader").start()

_UNSAFE_URL_TOKENS: re.Pattern = re.compile(
    r"porn|xxx|nsfw|nude|naked|hentai|gore|snuff|fetish|escort|sexy|boob|tit|"
    r"camgirl|webcam[-_ ]?girl|strip[-_ ]?club|topless|shirtless|"
    r"darknet|dark[-_ ]?web|torrent|warez|crack[-_ ]?download|"
    r"proxy[-_ ]?unblocker|unblock[-_ ]?site|bypass[-_ ]?filter|"
    r"masturbat|blowjob|handjob|orgasm|vibrator|dildo|lingerie|thong",
    re.IGNORECASE,
)


def _score_query(query: str) -> tuple[int, str, str, str, str]:
    query_lower = query.lower()
    top_risk = 0
    top_label = ""
    top_message = ""
    top_hotline = ""
    top_cat = ""
    for pattern, risk, label, message, hotline, cat in _BLOCK_RULES:
        if pattern.search(query_lower) and risk > top_risk:
            top_risk = risk
            top_label = label
            top_message = message
            top_hotline = hotline
            top_cat = cat
    if top_risk == 0:
        return 0, "", "", "", ""
    if top_cat not in _NEVER_REDUCE and _has_educational_context(query_lower):
        top_risk = max(0, top_risk - _EDUCATIONAL_SCORE_REDUCTION)
    return top_risk, top_label, top_message, top_hotline, top_cat


def _extract_host(url: str) -> str:
    if "://" not in url:
        return ""
    return url.split("://", 1)[1].split("/", 1)[0].split(":")[0].lower()


def _is_domain_blocked(host: str) -> bool:
    if not host:
        return False
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in _blocked_domains:
            return True
    return False


@t.final
class SXNGPlugin(Plugin):
    id = "content_filter"

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.info = PluginInfo(
            id=self.id,
            name="Content Filter",
            description="Risk-scored filtering for dangerous, illegal, or age-inappropriate content.",
            preference_section="general",
        )

    def pre_search(self, request: "SXNG_Request", search: "SearchWithPlugins") -> bool:
        query = search.search_query.query.strip()
        if not query:
            return True
        risk, label, message, hotline, cat = _score_query(query)
        flask.g.risk_score = risk
        flask.g.risk_label = label
        if risk >= 80:
            request.blocked_message = message
            request.blocked_hotline = hotline
            request.blocked_label = label
            flask.g.content_blocked = True
            log.info("Content filter blocked query (risk=%d, cat=%s): %r", risk, label, query)
            return False
        return True

    def on_result(self, request: "SXNG_Request", search: "SearchWithPlugins", result: dict) -> bool:
        url = result.get("url", "") or ""
        host = _extract_host(url)
        if _is_domain_blocked(host):
            log.info("Blocklist suppressed domain: %s", host)
            return False
        if _UNSAFE_URL_TOKENS.search(url.lower()):
            log.info("URL token filter suppressed: %s", url[:120])
            return False
        risk = getattr(flask.g, "risk_score", 0)
        if risk <= 0:
            return True
        text_parts: list[str] = []
        for key in ("title", "url", "content", "parsed_url", "img_src", "thumbnail"):
            val = result.get(key)
            if val:
                text_parts.append(str(val).lower())
        searchable = " ".join(text_parts)
        if not searchable:
            return True
        threshold = 0 if risk >= 60 else (risk if risk >= 30 else 80)
        for pattern, rule_risk, _label, _msg, _hl, _cat in _BLOCK_RULES:
            if rule_risk >= threshold and pattern.search(searchable):
                log.info("Content filter suppressed result (risk=%d): %s", risk, result.get("url", "?"))
                return False
        return True

    def post_search(self, request: "SXNG_Request", search: "SearchWithPlugins"):
        message = getattr(request, "blocked_message", None)
        if not message:
            return []
        hotline = getattr(request, "blocked_hotline", "")
        parts = [message]
        if hotline:
            parts.append(hotline)
        return [Answer(answer=" ".join(parts))]
