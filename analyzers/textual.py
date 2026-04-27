"""
Textual / Linguistic analyzers:
- Stopword count
- Typos (misspelled words)
- First-person pronouns
- Urgency tone detection
- Request for action (imperative phrases)
- Financial & crypto patterns
- Foreign language detection
- Character frequency analysis (chi-squared)
- Flesch-Kincaid Grade Level
- Gunning Fog Index
"""

import re
import json
import math
import logging
from pathlib import Path
from collections import Counter

import textstat

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data file loaders
# ---------------------------------------------------------------------------
_DATA_DIR = Path(__file__).parent.parent / "data"


def _load_stopwords() -> set:
    """Load stopwords using NLTK corpus (primary), with static file fallback."""
    words = set()
    try:
        import nltk
        try:
            from nltk.corpus import stopwords as nltk_stopwords
            words = set(nltk_stopwords.words("english"))
            logger.debug(f"Loaded {len(words)} stopwords from NLTK")
        except LookupError:
            # Download if not present (happens on first run / Docker build)
            nltk.download("stopwords", quiet=True)
            from nltk.corpus import stopwords as nltk_stopwords
            words = set(nltk_stopwords.words("english"))
            logger.debug(f"Downloaded and loaded {len(words)} NLTK stopwords")
    except Exception as e:
        logger.warning(f"NLTK stopwords unavailable ({e}), using static file")

    # Merge with static file for anything NLTK might miss
    path = _DATA_DIR / "stopwords.txt"
    if path.exists():
        static = {
            line.strip().lower()
            for line in path.read_text().splitlines()
            if line.strip()
        }
        words |= static

    if not words:
        logger.warning("No stopwords loaded from any source")
    return words


def _load_english_freq() -> dict:
    path = _DATA_DIR / "english_freq.json"
    if path.exists():
        return json.loads(path.read_text())
    return {}


STOPWORDS = _load_stopwords()
ENGLISH_FREQ = _load_english_freq()


def _load_symspell():
    """Load SymSpell dictionary once at module level."""
    try:
        from symspellpy import SymSpell
        import importlib.resources
        sym = SymSpell(max_dictionary_edit_distance=2, prefix_length=7)
        try:
            dict_path = str(
                importlib.resources.files("symspellpy")
                / "frequency_dictionary_en_82_765.txt"
            )
        except Exception:
            import symspellpy as _sp
            dict_path = str(
                Path(_sp.__file__).parent / "frequency_dictionary_en_82_765.txt"
            )
        sym.load_dictionary(dict_path, term_index=0, count_index=1)
        return sym
    except Exception as e:
        logger.warning(f"symspellpy init failed: {e}")
        return None


SYMSPELL = _load_symspell()

# ---------------------------------------------------------------------------
# Urgency keywords/phrases
# ---------------------------------------------------------------------------
# Sources: APWG eCrime reports, Proofpoint Human Factor Reports,
# Cofense Annual Phishing Reports, Verizon DBIR social engineering data.
URGENCY_PHRASES = [
    # English
    "immediately", "urgent", "urgently", "act now", "right away",
    "your account will be suspended", "your account has been",
    "account will be closed", "account will be locked",
    "account has been compromised", "account has been locked",
    "account has been suspended", "expire", "expiring", "expired",
    "limited time", "time sensitive", "within 24 hours",
    "within 48 hours", "within 72 hours", "do not delay",
    "respond immediately", "failure to", "final warning",
    "final notice", "last chance", "do not ignore",
    "action required", "immediate action", "immediate attention",
    "as soon as possible", "right now", "without delay",
    "before it's too late", "limited offer",
    "required immediately", "response required",
    "don't miss", "risk of losing", "risk of suspension",
    "account at risk", "important update", "important notice",
    "critical update", "mandatory update", "attention needed",
    "attention required", "resolve immediately",
    "must be completed", "must respond",
    "only hours left", "only days left", "don't wait", "hurry",
    "important security update", "critical security alert",
    "requires your immediate", "will be permanently",
    "will result in", "consequences if",
    # Portuguese
    "este email expira", "expiram hoje", "urgente",
    "ação imediata", "atenção", "prazo final",
    # Spanish
    "acción inmediata", "aviso urgente", "plazo final",
    # French
    "action immédiate", "avis urgent", "délai final",
    # German
    "sofortige aktion", "dringend", "frist",
]

ACTION_PHRASES = [
    # English — click/tap
    "click here", "click below", "click the link",
    "click the button", "click now", "click to",
    "tap here", "tap below", "open link",
    "follow the link", "use the link", "go to the",
    "scan qr code", "scan the code", "open in browser",
    # English — account actions
    "update now", "update your", "verify now",
    "verify your account", "verify your identity",
    "verify your information", "verify your email",
    "confirm your", "confirm your identity",
    "reset your password", "change your password",
    "log in now", "login now", "sign in now",
    "sign in immediately", "access now",
    "download the attachment", "open the attachment",
    "review your account", "secure your account",
    "reactivate your", "restore your",
    "submit your", "provide your", "enter your",
    "validate your", "authorize your",
    "open the official", "open the document", "open the file",
    "view the document", "view your", "access your",
    "access the", "get started", "proceed to",
    "activate your", "complete your", "manage your",
    "review document", "view invoice",
    "accept invitation", "join now",
    "register now", "apply now", "continue to",
    "download document", "preview document",
    "connect your wallet", "approve transaction",
    # Portuguese
    "clique aqui", "atualize agora", "resgate agora",
    "resgatar agora", "acesse agora", "abra o documento",
    # Spanish
    "haga clic aquí", "actualice ahora", "acceda ahora",
    # French
    "cliquez ici", "mettez à jour", "accédez maintenant",
    # German
    "klicken sie hier", "jetzt aktualisieren", "jetzt zugreifen",
]

FIRST_PERSON_PATTERN = re.compile(
    r"\b(I|me|my|mine|myself|we|us|our|ours|ourselves)\b",
    re.IGNORECASE,
)

# Financial & crypto patterns
BITCOIN_PATTERN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BITCOIN_BECH32_PATTERN = re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,89}\b")
ETHEREUM_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BANK_ACCOUNT_PATTERN = re.compile(
    r"\b\d{8,17}\b"  # Generic bank account number pattern
)
FINANCIAL_KEYWORDS = [
    # Wire/bank transfers
    "wire transfer", "bank transfer", "western union",
    "moneygram", "money order", "direct deposit",
    "routing number", "account number", "swift code",
    "iban", "ach transfer", "sort code",
    # Crypto
    "bitcoin", "btc", "ethereum", "eth",
    "cryptocurrency", "crypto wallet", "wallet address",
    "seed phrase", "private key", "nft", "defi",
    "airdrop", "staking", "metamask", "connect wallet",
    # Payment platforms
    "paypal", "venmo", "zelle", "cashapp", "cash app",
    "stripe", "wise", "revolut", "google pay", "apple pay",
    # Card info
    "credit card", "debit card", "card number",
    "cvv", "expiry date", "billing address",
    # Multilingual
    "transferência", "pix", "boleto", "virement",
    "überweisung", "transferencia",
]


def _clean_urls_from_text(text: str) -> str:
    """Remove URLs from text before spell checking."""
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(r"www\.\S+", "", text)
    text = re.sub(r"\S+@\S+", "", text)
    return text


def _tokenize(text: str) -> list[str]:
    """Tokenize text into words."""
    return re.findall(r"[a-zA-Z]+", text)


# ---------------------------------------------------------------------------
# 1. Stopword Count
# ---------------------------------------------------------------------------

def count_stopwords(body_text: str) -> dict:
    """Count stopwords in the email body."""
    words = _tokenize(body_text.lower())
    count = sum(1 for w in words if w in STOPWORDS)
    return {
        "stopword_count": count,
        "total_words": len(words),
        "ratio": round(count / max(len(words), 1), 4),
    }


# ---------------------------------------------------------------------------
# 2. Typos (Misspelled Words)
# ---------------------------------------------------------------------------

def count_typos(body_text: str) -> dict:
    """Count misspelled words using symspellpy."""
    result = {
        "typo_count": 0,
        "total_checked": 0,
        "misspelled_samples": [],
    }

    sym = SYMSPELL
    if sym is None:
        result["error"] = "symspellpy unavailable"
        return result

    # Clean URLs first
    cleaned = _clean_urls_from_text(body_text)
    words = _tokenize(cleaned)

    # Filter very short and very long words
    words = [w for w in words if 2 < len(w) < 25]
    result["total_checked"] = len(words)

    typo_count = 0
    samples = []

    for word in words:
        suggestions = sym.lookup(
            word.lower(),
            verbosity=0,  # Top suggestion only
            max_edit_distance=2,
        )
        if not suggestions or suggestions[0].distance > 0:
            typo_count += 1
            if len(samples) < 10:
                samples.append(word)

    result["typo_count"] = typo_count
    result["misspelled_samples"] = samples
    return result


# ---------------------------------------------------------------------------
# 3. First-Person Pronouns
# ---------------------------------------------------------------------------

def count_first_person(subject: str, body_text: str) -> dict:
    """Count first-person pronouns in subject and body."""
    combined = f"{subject} {body_text}"
    matches = FIRST_PERSON_PATTERN.findall(combined)
    return {
        "count": len(matches),
        "words_found": dict(Counter(w.lower() for w in matches)),
    }


# ---------------------------------------------------------------------------
# 4. Urgency Tone
# ---------------------------------------------------------------------------

def detect_urgency(subject: str, body_text: str) -> dict:
    """Detect urgency language in the email."""
    combined = f"{subject} {body_text}".lower()
    found = []

    for phrase in URGENCY_PHRASES:
        if phrase in combined:
            count = combined.count(phrase)
            found.append({"phrase": phrase, "count": count})

    return {
        "urgency_detected": len(found) > 0,
        "urgency_phrases": found,
        "total_matches": sum(f["count"] for f in found),
    }


# ---------------------------------------------------------------------------
# 5. Request for Action
# ---------------------------------------------------------------------------

def detect_action_requests(subject: str, body_text: str) -> dict:
    """Detect imperative phrases demanding immediate action."""
    combined = f"{subject} {body_text}".lower()
    found = []

    for phrase in ACTION_PHRASES:
        if phrase in combined:
            count = combined.count(phrase)
            found.append({"phrase": phrase, "count": count})

    return {
        "action_requested": len(found) > 0,
        "action_phrases": found,
        "total_matches": sum(f["count"] for f in found),
    }


# ---------------------------------------------------------------------------
# 6. Financial & Crypto Patterns
# ---------------------------------------------------------------------------

def detect_financial_patterns(body_text: str) -> dict:
    """Detect Bitcoin/Ethereum addresses, bank accounts, money transfer language."""
    result = {
        "bitcoin_addresses": [],
        "ethereum_addresses": [],
        "financial_keywords": [],
        "has_crypto": False,
        "has_financial_language": False,
    }

    # Crypto addresses
    btc = BITCOIN_PATTERN.findall(body_text)
    btc_bech32 = BITCOIN_BECH32_PATTERN.findall(body_text)
    eth = ETHEREUM_PATTERN.findall(body_text)

    result["bitcoin_addresses"] = list(set(btc + btc_bech32))[:10]
    result["ethereum_addresses"] = list(set(eth))[:10]
    result["has_crypto"] = bool(result["bitcoin_addresses"] or result["ethereum_addresses"])

    # Financial keywords
    body_lower = body_text.lower()
    for keyword in FINANCIAL_KEYWORDS:
        if keyword in body_lower:
            count = body_lower.count(keyword)
            result["financial_keywords"].append({"keyword": keyword, "count": count})

    result["has_financial_language"] = bool(result["financial_keywords"])

    return result


# ---------------------------------------------------------------------------
# 7. Foreign Language Detection
# ---------------------------------------------------------------------------

def detect_foreign_language(body_text: str) -> dict:
    """Detect non-English text and report language frequencies."""
    result = {
        "detected_languages": [],
        "primary_language": "unknown",
        "is_multilingual": False,
        "non_english_ratio": 0.0,
    }

    if not body_text or len(body_text.strip()) < 20:
        return result

    try:
        from langdetect import detect_langs, DetectorFactory
        DetectorFactory.seed = 0  # Deterministic

        langs = detect_langs(body_text)
        result["detected_languages"] = [
            {"lang": str(lang.lang), "probability": round(lang.prob, 4)}
            for lang in langs
        ]

        if langs:
            result["primary_language"] = str(langs[0].lang)

        # Check for multilingual content
        non_english = [l for l in langs if str(l.lang) != "en"]
        result["is_multilingual"] = len(langs) > 1
        result["non_english_ratio"] = round(
            sum(l.prob for l in non_english), 4
        ) if non_english else 0.0

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# ---------------------------------------------------------------------------
# 8. Character Frequency (Chi-Squared)
# ---------------------------------------------------------------------------

def analyze_char_frequency(body_text: str) -> dict:
    """Chi-squared test of letter distribution vs standard English frequencies."""
    result = {
        "chi_squared": 0.0,
        "matches_english": True,
        "letter_distribution": {},
    }

    if not body_text or not ENGLISH_FREQ:
        return result

    # Count only alphabetic characters
    letters = [c.lower() for c in body_text if c.isalpha()]
    if len(letters) < 50:
        return result

    total = len(letters)
    observed = Counter(letters)

    chi_sq = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        obs = observed.get(letter, 0)
        exp = (expected_pct / 100.0) * total
        if exp > 0:
            chi_sq += ((obs - exp) ** 2) / exp

    result["chi_squared"] = round(chi_sq, 2)
    # With 25 degrees of freedom, critical value at p=0.05 is ~37.65
    result["matches_english"] = chi_sq < 100  # Lenient threshold

    # Top deviations
    dist = {}
    for letter, expected_pct in ENGLISH_FREQ.items():
        obs_pct = (observed.get(letter, 0) / total) * 100
        dist[letter] = round(obs_pct, 2)
    result["letter_distribution"] = dist

    return result


# ---------------------------------------------------------------------------
# 9. Flesch-Kincaid Grade Level
# ---------------------------------------------------------------------------

def compute_flesch_kincaid(body_text: str) -> dict:
    """Compute readability score — FK grade level."""
    result = {
        "grade_level": 0.0,
        "reading_ease": 0.0,
        "8th_grader_readable": True,
    }

    if not body_text or len(body_text.strip()) < 20:
        return result

    try:
        result["grade_level"] = round(textstat.flesch_kincaid_grade(body_text), 2)
        result["reading_ease"] = round(textstat.flesch_reading_ease(body_text), 2)
        result["8th_grader_readable"] = result["grade_level"] <= 8.0
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# ---------------------------------------------------------------------------
# 10. Gunning Fog Index
# ---------------------------------------------------------------------------

def compute_gunning_fog(body_text: str) -> dict:
    """Compute Gunning Fog Index — years of formal education needed."""
    result = {
        "fog_index": 0.0,
        "education_years": 0,
    }

    if not body_text or len(body_text.strip()) < 20:
        return result

    try:
        fog = textstat.gunning_fog(body_text)
        result["fog_index"] = round(fog, 2)
        result["education_years"] = round(fog)
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_textual_checks(parsed_email) -> dict:
    """Run all textual/linguistic checks on a parsed email."""
    body = parsed_email.body_text
    subject = parsed_email.subject
    results = {}

    results["stopwords"] = count_stopwords(body)
    results["typos"] = count_typos(body)
    results["first_person_pronouns"] = count_first_person(subject, body)
    results["urgency"] = detect_urgency(subject, body)
    results["action_requests"] = detect_action_requests(subject, body)
    results["financial_crypto"] = detect_financial_patterns(body)
    results["foreign_language"] = detect_foreign_language(body)
    results["char_frequency"] = analyze_char_frequency(body)
    results["flesch_kincaid"] = compute_flesch_kincaid(body)
    results["gunning_fog"] = compute_gunning_fog(body)
    results["body_word_count"] = len(_tokenize(body))

    return results
