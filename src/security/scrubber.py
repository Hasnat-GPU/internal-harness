"""SEC-01: Pre-tokenization secret & PII scrubber.

Every ``context_text`` and ``expected_action`` passes through :func:`scrub` before it is stored in
SQLite or tokenized, so secrets can never be baked into ``.safetensors`` weights.

Detection runs on a folded copy of the text (NFKD per character, combining marks and invisible
characters removed), so zero-width, fullwidth, accent or bidi tricks cannot split a secret past the
patterns. Redactions are mapped back onto the original text, so everything else keeps its exact
spelling. Detectors:

* known credential formats: OpenAI/Anthropic ``sk-``, Google ``AIza``/``ya29.``, GitHub, GitLab,
  AWS, Slack, Stripe, Hugging Face, npm, JWTs, Bearer/Basic/Authorization headers, PEM private
  keys, credentials in URLs and ``password=``-style assignments;
* PII: emails (including ``[at]``/``(dot)``/``%40`` obfuscations) and IPv4 addresses. Loopback and
  0.0.0.0 identify nothing and are kept, so rules such as "bind to 127.0.0.1" survive;
* entropy: any token of >= 24 chars with H > 4.5 bits/char (Blueprint SEC-01), plus two additions
  the blueprint threshold needs: hex tokens of >= 32 chars with H > 3.0 (hex never exceeds 4.0
  bits/char, so ``X_HARNESS_TOKEN`` would pass), and "generated" tokens of 24-63 chars (the plain
  estimate of H runs low on short strings, so only ~62% of random 32-char keys reach 4.5; see
  :meth:`SecretScrubber.is_generated`).

Every hit becomes ``<REDACTED_SECRET>``. Results record only the kind and position of each
redaction, never the secret, so they are safe to log.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

REDACTION_TOKEN = "<REDACTED_SECRET>"
ENTROPY_THRESHOLD_BITS = 4.5
ENTROPY_MIN_LENGTH = 24
HEX_ENTROPY_THRESHOLD_BITS = 3.0
HEX_MIN_LENGTH = 32
GENERATED_MAX_LENGTH = 64  # from 64 chars on, H > 4.5 alone catches random tokens (>= 99.9%)
GENERATED_MIN_CLASS_SWITCH = 0.40

# ----------------------------------------------------------------------------- text forms

_INVISIBLE_LETTERS = frozenset("\u115f\u1160\u3164\uffa0\u2800")  # letters that render as blank space
_DROP_FROM_TEXT = frozenset({"Cc", "Cf", "Cs", "Co"})  # controls, zero-width/bidi/tag chars, surrogates, private use
_DROP_FROM_DETECTION = _DROP_FROM_TEXT | {"Cn", "Mn", "Me"}  # + unassigned code points and combining marks
_ASCII_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _visible(ch: str, dropped: frozenset[str]) -> bool:
    return ch in "\n\t" or (ch not in _INVISIBLE_LETTERS and unicodedata.category(ch) not in dropped)


def clean_text(text: str) -> str:
    """Stored form of event text: ``\\n`` line endings, invisible/control characters removed, NFC."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.isascii():
        return _ASCII_CONTROLS.sub("", text)
    return unicodedata.normalize("NFC", "".join(ch for ch in text if _visible(ch, _DROP_FROM_TEXT)))


def fold_text(text: str) -> tuple[str, list[int] | None]:
    """Detection form of `text`, plus the index in `text` that each folded character came from.

    Each character is NFKD-decomposed on its own (``ｓｋ－`` becomes ``sk-``) and combining marks are
    dropped (``á`` becomes ``a``, so an accent composed onto a key cannot split it), as are invisible
    characters. A ``None`` mapping means identity (plain ASCII input).
    """
    if text.isascii() and not _ASCII_CONTROLS.search(text):
        return text, None
    chars: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(text):
        for folded in ch if ch.isascii() else unicodedata.normalize("NFKD", ch):
            if _visible(folded, _DROP_FROM_DETECTION):
                chars.append(folded)
                origin.append(i)
    return "".join(chars), origin


def canonicalize(text: str) -> str:
    """The form every security check reads: :func:`clean_text`, then :func:`fold_text`."""
    return fold_text(clean_text(text))[0]


def shannon_entropy(value: str) -> float:
    """Shannon entropy of `value` in bits per character."""
    if not value:
        return 0.0
    n = len(value)
    return sum(count / n * math.log2(n / count) for count in Counter(value).values())


def miller_madow_entropy(value: str) -> float:
    """Shannon entropy plus the Miller-Madow small-sample bias correction, (distinct - 1) / (2 n ln 2)."""
    if not value:
        return 0.0
    return shannon_entropy(value) + (len(set(value)) - 1) / (2 * len(value) * math.log(2))


def class_switch_rate(value: str) -> float:
    """Share of adjacent characters that change class (upper / lower / digit / other)."""
    if len(value) < 2:
        return 0.0
    classes = [0 if c.isupper() else 1 if c.islower() else 2 if c.isdigit() else 3 for c in value]
    return sum(a != b for a, b in pairwise(classes)) / (len(value) - 1)


# ----------------------------------------------------------------------------- value checks

_NON_SECRET_LITERALS = frozenset(
    {"true", "false", "none", "null", "nil", "undefined", "yes", "no", "on", "off",
     "required", "optional", "redacted", "hidden", "masked"}
)
_CODE_REFERENCE = re.compile(
    r"(?:\$|%|\{\{|<|os\.environ|os\.getenv|getenv\(|process\.env|env\(|env\[|secrets\.|config\.|settings\.|self\.)",
    re.IGNORECASE,
)


def _unquote(value: str) -> str:
    return value.strip().strip("\"'`")


def _is_assigned_secret(value: str) -> bool:
    """A literal after ``password=`` / ``token:`` rather than a placeholder or a code reference."""
    v = _unquote(value)
    if len(v) < 4 or REDACTION_TOKEN in v:
        return False
    if v.lower() in _NON_SECRET_LITERALS or set(v) <= set("*xX.-_#?"):
        return False
    if _CODE_REFERENCE.match(v):
        return False
    return not (v.isdigit() and len(v) < 6)


def _looks_generated(value: str) -> bool:
    """Credential-shaped rather than prose: a digit or symbol, or several capitals among lowercase."""
    v = _unquote(value)
    if len(v) < 8 or REDACTION_TOKEN in v:
        return False
    if any(c.isdigit() or c in "-._~+/=!#$%&*?@^" for c in v):
        return True
    return sum(c.isupper() for c in v) >= 2 and any(c.islower() for c in v)


def _is_basic_credential(value: str) -> bool:
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    return b":" in raw and all(32 <= b < 127 for b in raw)


def _is_identifying_ipv4(value: str) -> bool:
    return not (value.startswith("127.") or value == "0.0.0.0")


# ----------------------------------------------------------------------------- detectors

@dataclass(frozen=True, slots=True)
class _Detector:
    kind: str
    pattern: re.Pattern[str]
    group: str | int = 0  # part of the match that is redacted (e.g. keep "Bearer " for context)
    accept: Callable[[str], bool] | None = None


# Every pattern that starts with a repeated character class is anchored with a look-behind on the
# same class, so a hostile input cannot trigger quadratic backtracking (ReDoS).
_TOKEN_START = r"(?<![A-Za-z0-9_\-])"
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_AT = r"(?:@|%40|\s*[\[({<]\s*(?:at|@)\s*[\])}>]\s*)"
_DOT = r"(?:\.|\s*[\[({<]\s*(?:dot|\.)\s*[\])}>]\s*)"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
_CREDENTIAL_NAME = (
    r"(?:password|passwd|passphrase|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|secret[_\-]?key"
    r"|private[_\-]?key|signing[_\-]?key|encryption[_\-]?key|master[_\-]?key|auth[_\-]?key"
    r"|client[_\-]?secret|credentials?)"
)


def _d(kind: str, pattern: str, flags: int = 0, group: str | int = 0,
       accept: Callable[[str], bool] | None = None) -> _Detector:
    return _Detector(kind, re.compile(pattern, flags), group, accept)


_DETECTORS: tuple[_Detector, ...] = (
    _d("private_key",
       r"-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----"
       r"(?:.*?-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\s:,.\-\\]*)", re.DOTALL),
    _d("anthropic_key", _TOKEN_START + r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    _d("openai_key", _TOKEN_START + r"sk-[A-Za-z0-9_\-]{16,}"),
    _d("stripe_key", _TOKEN_START + r"[rs]k_(?:live|test)_[A-Za-z0-9]{10,}"),
    _d("google_api_key", _TOKEN_START + r"AIza[0-9A-Za-z_\-]{30,}"),
    _d("google_oauth", _TOKEN_START + r"(?:ya29\.[0-9A-Za-z_\-]{20,}|GOCSPX-[0-9A-Za-z_\-]{20,})"),
    _d("github_token", _TOKEN_START + r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    _d("gitlab_token", _TOKEN_START + r"glpat-[A-Za-z0-9_\-]{20,}"),
    _d("aws_access_key_id",
       r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA|ASCA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
    _d("aws_secret",
       r"aws_?(?:secret_?access_?key|secret_?key|session_?token)[\"']?\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=]{16,})",
       re.IGNORECASE, "secret"),
    _d("slack_token", _TOKEN_START + r"xox[abposr]-[A-Za-z0-9\-]{10,}"),
    _d("huggingface_token", _TOKEN_START + r"hf_[A-Za-z0-9]{30,}"),
    _d("npm_token", _TOKEN_START + r"npm_[A-Za-z0-9]{30,}"),
    _d("jwt", _TOKEN_START + r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),
    _d("authorization_header",
       r"\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?(?:(?:bearer|basic|token|digest|apikey|key)\s+)?"
       r"(?P<secret>[^\s\"',;<>]{8,})", re.IGNORECASE, "secret", _looks_generated),
    _d("bearer_token", r"\bbearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{8,}=*)", re.IGNORECASE, "secret", _looks_generated),
    _d("basic_auth", r"\bbasic\s+(?P<secret>[A-Za-z0-9+/]{8,}={0,2})", re.IGNORECASE, "secret", _is_basic_credential),
    _d("cli_credentials", r"(?<!\S)(?:-u|--user)[\s=]+[\"']?(?P<secret>[^\s:\"']+:[^\s\"']+)", group="secret"),
    _d("url_credentials", r"(?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]*://(?P<secret>[^\s/:@<>\"']*:[^\s/@<>\"']+)@",
       re.IGNORECASE, "secret"),
    _d("url_secret_param",
       r"[?&;](?:access_token|refresh_token|id_token|token|api_key|apikey|api-key|key|sig|signature|secret"
       r"|client_secret|password|passwd|pwd|auth|code|x-amz-signature|x-amz-credential|x-amz-security-token"
       r"|x-goog-signature|x-goog-credential)=(?P<secret>[^&\s#\"'<>]{6,})",
       re.IGNORECASE, "secret", _is_assigned_secret),
    _d("credential_assignment",
       r"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]*?" + _CREDENTIAL_NAME
       + r"[\"']?\s*(?::=|=>|[:=])\s*(?P<secret>\"[^\"\n]{4,}\"|'[^'\n]{4,}'|`[^`\n]{4,}`|[^\s\"'`,;]{4,})",
       re.IGNORECASE, "secret", _is_assigned_secret),
    _d("password_phrase", r"\b(?:password|passwd|passphrase|passcode)\s+(?:is|was)\s+[\"']?(?P<secret>[^\s\"']{6,})",
       re.IGNORECASE, "secret", _looks_generated),
    _d("email",
       r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+" + _AT + _LABEL + r"(?:" + _DOT + _LABEL + r")*" + _DOT
       + r"[A-Za-z]{2,24}", re.IGNORECASE),
    _d("ipv4", r"(?<![\w.])" + _OCTET + r"(?:\." + _OCTET + r"){3}(?![\w]|\.[0-9])", accept=_is_identifying_ipv4),
)
_ENTROPY_PRIORITY = len(_DETECTORS)


# ----------------------------------------------------------------------------- results

@dataclass(frozen=True, slots=True)
class Redaction:
    kind: str
    start: int  # offsets into the cleaned input text (see clean_text)
    end: int


@dataclass(frozen=True, slots=True)
class ScrubResult:
    text: str
    redactions: tuple[Redaction, ...] = ()

    @property
    def count(self) -> int:
        return len(self.redactions)

    def counts_by_kind(self) -> dict[str, int]:
        return dict(Counter(r.kind for r in self.redactions))


def _redact(text: str, spans: list[tuple[int, int, int, str]]) -> ScrubResult:
    """Merge overlapping/touching spans (keeping the highest-priority kind) and replace each."""
    if not spans:
        return ScrubResult(text)
    spans.sort(key=lambda s: (s[0], -s[1], s[2]))
    merged: list[list[Any]] = []
    for start, end, priority, kind in spans:
        if merged and start <= merged[-1][1]:
            last = merged[-1]
            last[1] = max(last[1], end)
            if priority < last[2]:
                last[2], last[3] = priority, kind
        else:
            merged.append([start, end, priority, kind])
    pieces: list[str] = []
    cursor = 0
    for start, end, _, _ in merged:
        pieces += (text[cursor:start], REDACTION_TOKEN)
        cursor = end
    pieces.append(text[cursor:])
    return ScrubResult("".join(pieces), tuple(Redaction(kind, s, e) for s, e, _, kind in merged))


# ----------------------------------------------------------------------------- scrubber

class SecretScrubber:
    """Deterministic regex + Shannon-entropy redactor (SEC-01)."""

    def __init__(
        self,
        *,
        entropy_threshold: float = ENTROPY_THRESHOLD_BITS,
        entropy_min_length: int = ENTROPY_MIN_LENGTH,
        hex_entropy_threshold: float = HEX_ENTROPY_THRESHOLD_BITS,
        hex_min_length: int = HEX_MIN_LENGTH,
        generated_max_length: int = GENERATED_MAX_LENGTH,
        generated_min_class_switch: float = GENERATED_MIN_CLASS_SWITCH,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.hex_entropy_threshold = hex_entropy_threshold
        self.generated_max_length = generated_max_length
        self.generated_min_class_switch = generated_min_class_switch
        # "=" only as trailing base64 padding, so NAME=value is judged on the value and keeps its label.
        self._entropy_token = re.compile(rf"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{{{entropy_min_length},}}={{0,2}}")
        # Separator-free stretches inside a token: split at "/" too (path components), and not (base64 keys).
        self._stretches = (re.compile(rf"[A-Za-z0-9+]{{{entropy_min_length},}}"),
                           re.compile(rf"[A-Za-z0-9+/]{{{entropy_min_length},}}"))
        self._hex_token = re.compile(rf"(?<![A-Za-z0-9])(?:0x)?[0-9a-fA-F]{{{hex_min_length},}}(?![A-Za-z0-9])")

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> SecretScrubber:
        sc = cfg["security"]["scrubber"]
        if sc.get("replacement_token", REDACTION_TOKEN) != REDACTION_TOKEN:
            raise ValueError(f"the SEC-01 placeholder is fixed to {REDACTION_TOKEN} by the blueprint")
        return cls(
            entropy_threshold=float(sc["entropy_threshold_bits"]),
            entropy_min_length=int(sc["entropy_min_length"]),
            hex_entropy_threshold=float(sc["hex_entropy_threshold_bits"]),
            hex_min_length=int(sc["hex_min_length"]),
            generated_max_length=int(sc["generated_max_length"]),
            generated_min_class_switch=float(sc["generated_min_class_switch"]),
        )

    def is_generated(self, value: str) -> bool:
        """A machine-generated token that the blueprint's H > 4.5 rule misses because it is short.

        The plain entropy estimate runs low on short strings: only ~5% / 62% / 97% of random base62
        strings of 24 / 32 / 40 chars reach 4.5 bits/char. A separator-free stretch of 24-63 chars is
        therefore also flagged when its bias-corrected (Miller-Madow) entropy exceeds the threshold and
        >= 40% of adjacent characters switch class, as generated text does and words, identifiers and
        paths do not. Calibrated against 3.8k real identifiers/paths from the Python install: recall
        on random keys becomes ~92% / 99.5% / 100% at 24 / 32 / 40 chars, with 0.6% of long CamelCase
        names or URL paths redacted as the price.
        """
        return (len(value) < self.generated_max_length
                and miller_madow_entropy(value) > self.entropy_threshold
                and class_switch_rate(value) >= self.generated_min_class_switch)

    def scrub(self, text: str) -> ScrubResult:
        """Return the cleaned text with every secret / PII span replaced by ``<REDACTED_SECRET>``."""
        clean = clean_text(text)
        folded, origin = fold_text(clean)
        spans = [*self._pattern_spans(folded), *self._entropy_spans(folded)]
        if origin is not None:
            spans = [(origin[s], origin[e - 1] + 1, p, k) for s, e, p, k in spans]
        return _redact(clean, spans)

    def _pattern_spans(self, text: str) -> Iterator[tuple[int, int, int, str]]:
        for priority, det in enumerate(_DETECTORS):
            for m in det.pattern.finditer(text):
                if det.accept is None or det.accept(m.group(det.group)):
                    yield m.start(det.group), m.end(det.group), priority, det.kind

    def _entropy_spans(self, text: str) -> Iterator[tuple[int, int, int, str]]:
        for m in self._entropy_token.finditer(text):
            token, base = m.group(), m.start()
            if shannon_entropy(token) > self.entropy_threshold:  # the blueprint rule
                yield base, m.end(), _ENTROPY_PRIORITY, "high_entropy"
                continue
            # A random value can hide inside a longer run (URL path, snake_case join), and short random
            # values rarely reach 4.5 bits/char, so separator-free stretches are judged on their own.
            for pattern in self._stretches:
                for stretch in pattern.finditer(token):
                    value = stretch.group()
                    if shannon_entropy(value) > self.entropy_threshold:
                        kind = "high_entropy"
                    elif self.is_generated(value):
                        kind = "generated_token"
                    else:
                        continue
                    yield base + stretch.start(), base + stretch.end(), _ENTROPY_PRIORITY, kind
        for m in self._hex_token.finditer(text):
            digits = m.group().removeprefix("0x").removeprefix("0X")
            # Random hex all but surely holds a letter (P(none in 32 chars) ~ 3e-7); long decimal numbers do not.
            if shannon_entropy(m.group()) > self.hex_entropy_threshold and not digits.isdigit():
                yield m.start(), m.end(), _ENTROPY_PRIORITY + 1, "high_entropy_hex"


DEFAULT_SCRUBBER = SecretScrubber()


def scrub(text: str) -> ScrubResult:
    """Scrub `text` with the blueprint-default thresholds."""
    return DEFAULT_SCRUBBER.scrub(text)
