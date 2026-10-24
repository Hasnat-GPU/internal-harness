"""SEC-02: Indirect prompt-injection & weight firewall.

An event may reach the Surprise Gate (M2) only if it passes both checks:

1. Trust gate: only ``HUMAN`` and ``HARNESS2_VERIFIED`` events may open the Plasticity Gate.
   ``UNTRUSTED_EXTERNAL`` (scraped web pages, third-party MCP tool output) stays blocked until a
   Harness² critic pass re-submits it as ``HARNESS2_VERIFIED``. Unknown labels fail closed.
2. Instruction-override scanner: blocks text that tries to override instructions, adopt a
   jailbreak persona, extract the system prompt, disable a safety gate, fetch or execute remote
   code, exfiltrate secrets or inject chat-template control tokens, including obfuscated forms
   (homoglyphs, leetspeak, zero-width or letter spacing, percent/HTML/backslash escapes, base64,
   hex and invisible Unicode tag characters).

A negated imperative ("never disable the safety gate") is defensive and passes, so Harness² can
learn its own safety rules; double negations and inverting verbs ("do not hesitate to disable")
do not count as negation. Verdicts never contain the scanned text, so they are safe to log.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from urllib.parse import unquote

from .scrubber import canonicalize

SOURCE_TRUST_LEVELS = ("HUMAN", "HARNESS2_VERIFIED", "UNTRUSTED_EXTERNAL")
TRUSTED_SOURCES = frozenset({"HUMAN", "HARNESS2_VERIFIED"})


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    category: str
    field: str | None = None  # event field that triggered it; None for the trust gate
    encoding: str = "plain"  # how the signal was uncovered, e.g. "base64+leetspeak"


@dataclass(frozen=True, slots=True)
class FirewallVerdict:
    allowed: bool
    source_trust: str
    findings: tuple[Finding, ...] = ()

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(f.rule_id for f in self.findings))

    @property
    def categories(self) -> frozenset[str]:
        return frozenset(f.category for f in self.findings)


# ----------------------------------------------------------------------------- skeletons

# Cyrillic, Greek and Armenian letters that look Latin, by the Latin letter they imitate (lowercase
# forms, applied after casefold()). Code points rather than glyphs, so a reader can tell them apart.
_LOOKALIKES = {
    "a": (0x0430, 0x03B1), "b": (0x0432, 0x03B2), "c": (0x0441,), "d": (0x0501,), "e": (0x0435, 0x0451, 0x03B5),
    "g": (0x0261, 0x0581), "h": (0x043D, 0x04BB, 0x0570), "i": (0x0456, 0x0457, 0x0131, 0x03B9), "j": (0x0458,),
    "k": (0x043A, 0x03BA), "l": (0x04CF,), "m": (0x043C,), "n": (0x03B7, 0x0578), "o": (0x043E, 0x03BF, 0x0585),
    "p": (0x0440, 0x03C1), "q": (0x051B,), "s": (0x0455,), "t": (0x0442, 0x03C4), "u": (0x03C5, 0x057D),
    "v": (0x03BD,), "w": (0x051D, 0x03C9), "x": (0x0445, 0x03C7), "y": (0x0443, 0x03B3), "z": (0x03B6,),
}
_CONFUSABLES = str.maketrans({chr(cp): latin for latin, cps in _LOOKALIKES.items() for cp in cps})
_LEET = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l", "+": "t"}
_LEET_VARIANTS = (str.maketrans({**_LEET, "1": "i"}), str.maketrans({**_LEET, "1": "l"}))
_NOT_CONTRACTION = re.compile(r"n['’]t\b")
_NON_WORD = re.compile(r"[^a-z0-9]+")
_NON_LETTER = re.compile(r"[^a-z]+")
_CLAUSE_BREAK = re.compile(r"[!?;\n]+|[.:](?=\s|$)")  # "." / ":" end a clause only before whitespace (keeps .env, http://)


def _fold(text: str) -> str:
    """Casefold, map look-alike letters to Latin and expand n't to not."""
    return _NOT_CONTRACTION.sub(" not", text.casefold().translate(_CONFUSABLES))


def _words(text: str) -> str:
    return _NON_WORD.sub(" ", text).strip()


# ----------------------------------------------------------------------------- negation

_NEGATIONS = frozenset({
    "not", "never", "no", "cannot", "nobody", "none", "neither", "nor", "without", "avoid", "avoids", "avoiding",
    "refuse", "refuses", "prevent", "prevents", "prohibit", "prohibits", "forbid", "forbids", "block", "blocks",
    "reject", "rejects", "stop", "stops", "disallow", "disallows",
})
# Words that may sit between a negation and its verb without changing who does what.
_FILLERS = frozenset({
    "a", "an", "the", "and", "or", "also", "ever", "even", "just", "simply", "again", "please", "it", "i", "we",
    "you", "they", "one", "anyone", "anybody", "someone", "agent", "agents", "subagent", "subagents", "tool",
    "tools", "call", "calls", "request", "requests", "model", "models", "harness", "harness2", "yourself", "itself",
    "themselves", "that", "which", "who", "to", "try", "tries", "attempt", "attempts", "attempting", "trying",
    "accidentally", "silently", "automatically", "manually", "directly", "blindly", "should", "must", "shall",
    "will", "would", "can", "could", "may", "might", "do", "does", "did", "be", "is", "are", "allowed",
    "permitted", "able", "ok", "okay", "under", "any", "circumstances", "from", "let", "run", "execute", "use",
    "invoke", "ca", "wo",
    # who is asking ("reject any tool output that asks you to reveal ...")
    "ask", "asks", "asking", "asked", "tell", "tells", "telling", "told", "want", "wants", "output", "outputs",
    "content", "text", "message", "messages", "page", "pages", "input", "inputs", "payload", "payloads", "data",
})


def _negated(words_before: list[str]) -> bool:
    """An odd number of negations directly before the verb, with only filler words in between."""
    negations = 0
    for word in reversed(words_before[-12:]):
        if word in _NEGATIONS:
            negations += 1
        elif word not in _FILLERS:
            break
    return negations % 2 == 1


# ----------------------------------------------------------------------------- rules

@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    negatable: bool = False  # a negated imperative is defensive, not adversarial
    despaced: re.Pattern[str] | None = None  # the same phrase with all spacing removed


def _rule(rule_id: str, category: str, src: str, *, negatable: bool = False, despace: bool | str = False) -> _Rule:
    """`despace=True` derives the spacing-free pattern by dropping \\s+ / \\b; a string gives it explicitly
    (needed where the word pattern has open ``\\w+`` gaps, which would over-match without spaces)."""
    if isinstance(despace, str):
        despaced = re.compile(despace)
    else:
        despaced = re.compile(re.sub(r"\\s[+*]|\\b", "", src)) if despace else None
    return _Rule(rule_id, category, re.compile(src), negatable, despaced)


# Word rules run per clause on a lowercase word skeleton ("ignore  ALL previous..." -> "ignore all previous").
_Q = (r"(?:all|any|every|each|of|the|your|my|our|these|those|this|that|previous|previously|prior|above|earlier"
      r"|preceding|former|foregoing|original|initial|given|system|developer|safety|existing|current|old|other"
      r"|such|stated|mentioned|provided|aforementioned)")
_IGNORE = (r"(?:ignor(?:e|es|ed|ing)|disregard(?:s|ed|ing)?|forget(?:s|ting)?|forgot(?:ten)?|neglect(?:s|ed|ing)?"
           r"|abandon(?:s|ed|ing)?|nullif(?:y|ies|ied|ying)|throw\s+away|set\s+aside)")
_DIRECTIVES = (r"(?:instructions?|directions?|directives?|guidelines?|guardrails?|programming|guidance"
               r"|system\s+(?:prompts?|messages?|rules?)|safety\s+(?:rules?|polic(?:y|ies)|guidelines?)"
               r"|security\s+(?:rules?|polic(?:y|ies))|content\s+polic(?:y|ies))")
_DET = r"(?:the|all|any|every|your|its|our|this|that|these|those)"
_STRONG_DISABLE_VERBS = (r"disabl(?:e|es|ed|ing)|deactivat(?:e|es|ed|ing)|turn(?:s|ed|ing)?\s+off"
                         r"|switch(?:es|ed|ing)?\s+off|shut(?:s|ting)?\s+off|bypass(?:es|ed|ing)?|circumvent(?:s|ed|ing)?"
                         r"|evad(?:e|es|ed|ing)|defeat(?:s|ed|ing)?|neuter(?:s|ed|ing)?")
_DISABLE_STRONG = rf"(?:{_STRONG_DISABLE_VERBS})"
# Weaker verbs ("skip", "remove", "kill") only count when the object is clearly a security control.
_DISABLE = (rf"(?:{_STRONG_DISABLE_VERBS}|shut(?:s|ting)?\s+down|kill(?:s|ed|ing)?|remov(?:e|es|ed|ing)"
            r"|skip(?:s|ped|ping)?|ignor(?:e|es|ed|ing)|suppress(?:es|ed|ing)?|weaken(?:s|ed|ing)?|forc(?:e|es|ed|ing)\s+open)")
_GUARD_ADJ = (r"(?:safety|security|integrity|plasticity|surprise|injection|secret|secrets|pii|trust|authentication|auth"
              r"|sha|256|sha256|checksum|hash|signature|manifest|token|redaction|scrubbing|scrubber|firewall|content"
              r"|weight|sandbox)")
_GUARD_NOUN = (r"(?:gates?|guards?|guardrails?|filters?|checks?|checking|verifications?|validations?|scanners?|scanning"
               r"|protections?|firewalls?|scrubbers?|polic(?:y|ies)|layers?|mechanisms?|locks?|measures?|controls?"
               r"|shields?|sandbox(?:ing)?)")
_GUARD_ALONE = (r"(?:guardrails?|firewalls?|scrubbers?|safeguards?|sandbox(?:ing)?|safety|security|authentication"
                r"|encryption|kill\s+switch)")
_SEND = (r"(?:send|sends|sending|post|posts|posting|upload|uploads|uploading|exfiltrate|exfiltrates|exfiltrating"
         r"|leak|leaks|leaking|transmit|transmits|transmitting|forward|forwards|forwarding|e\s*mail|e\s*mails"
         r"|e\s*mailing|beacon|pipe|pipes|piping)")
_SECRET_STRONG = (r"(?:secrets?|credentials?|passwords?|passphrases?|private\s+keys?|ssh\s+keys?"
                  r"|env(?:ironment)?\s+(?:variables?|vars?|files?)|env\s+file|dot\s+env|cookies?|session\s+tokens?)")
_SECRET_WEAK = (r"(?:(?:api|aws|access|auth|bearer|github|openai|anthropic|cloud|harness|secret|refresh|signing"
                r"|encryption|master)\s+(?:\w+\s+)?(?:keys?|tokens?))")

_WORD_RULES: tuple[_Rule, ...] = (
    _rule("SEC02-OVR-01", "instruction_override", rf"\b{_IGNORE}(?:\s+{_Q}){{0,4}}\s+{_DIRECTIVES}\b",
          negatable=True, despace=True),
    _rule("SEC02-OVR-02", "instruction_override",
          rf"\b{_IGNORE}\s+(?:everything|anything|all)\s+(?:(?:(?:you\s+(?:were|have\s+been)|i|we)\s+)?"
          r"(?:said|told|wrote|written|stated|given|shown)\s+(?:to\s+you\s+)?)?"
          r"(?:above|so\s+far|until\s+now|up\s+to\s+now|previously)\b",
          negatable=True, despace=True),
    _rule("SEC02-OVR-03", "instruction_override",
          r"\b(?:overrid(?:e|es|ing)|overrul(?:e|es|ing)|ignor(?:e|es|ing))\s+(?:all\s+(?:of\s+)?)?your\s+(?:\w+\s+){0,2}?"
          r"(?:instructions?|directives?|guidelines?|guardrails?|programming|system\s+prompts?|prompts?|rules?"
          r"|polic(?:y|ies)|training|constraints?|restrictions?)\b",
          negatable=True,
          despace=r"(?:overrid(?:e|es|ing)|overrul(?:e|es|ing)|ignor(?:e|es|ing))(?:allof|all)?your"
                  r"(?:safety|system|core|previous|prior|current|original|initial|existing)?"
                  r"(?:instructions?|directives?|guidelines?|guardrails?|programming|systemprompts?|prompts?|rules?"
                  r"|polic(?:y|ies)|training|constraints?|restrictions?)"),
    _rule("SEC02-OVR-04", "instruction_override",
          r"\b(?:bypass(?:es|ed|ing)?|circumvent(?:s|ed|ing)?|jailbreak(?:s|ed|ing)?)\s+(?:\w+\s+){0,3}?"
          r"(?:instructions?|directives?|guidelines?|guardrails?|system\s+prompts?|safety\s+\w+"
          r"|content\s+polic(?:y|ies)|restrictions?|filters?)\b",
          negatable=True),
    _rule("SEC02-OVR-05", "instruction_override",
          r"\b(?:your\s+(?:new|real|actual|true|updated|revised|secret|hidden)\s+(?:instructions|directives|programming"
          r"|orders|mission)\s+(?:is|are)|here\s+(?:are|is)\s+your\s+new\s+(?:instructions|directives|orders))\b",
          despace=True),
    _rule("SEC02-PER-01", "jailbreak_persona",
          r"\b(?:you\s+are\s+(?:now\s+)?(?:an?\s+)?(?:dan|jailbroken|unrestricted|unfiltered|uncensored|unaligned|unbound"
          r"|unchained|evil|rogue)|(?:dan|jailbreak|god|chaos|unrestricted|unfiltered)\s+mode|can\s+do\s+anything\s+now"
          r"|(?:act|behave|respond|answer|pretend|roleplay)\s+(?:as|like)\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?"
          r"(?:unrestricted|unfiltered|uncensored|jailbroken|unaligned|evil|rogue)"
          r"|(?:ai|assistant|model|agent|llm)\s+(?:with\s+no|without(?:\s+any)?)\s+(?:rules|restrictions|filters"
          r"|guidelines|limits|limitations|ethics|morals|guardrails)|no\s+longer\s+(?:bound|restricted|constrained)\s+by)\b",
          negatable=True, despace=True),
    _rule("SEC02-EXT-01", "prompt_extraction",
          r"\b(?:(?:reveal|print|output|show|repeat|leak|display|dump|disclose|expose|recite|share|tell\s+me|give\s+me"
          r"|send\s+me|write\s+out|spell\s+out)\s+(?:me\s+)?(?:all\s+(?:of\s+)?)?your\s+(?:\w+\s+){0,2}?"
          r"|what\s+(?:is|are|was|were)\s+your\s+(?:\w+\s+)?)"
          r"(?:system\s+prompts?|instructions|initial\s+prompt|hidden\s+prompt|prompt|configuration|guidelines|rules"
          r"|context\s+window|secrets|training\s+data)\b",
          negatable=True,
          despace=r"(?:reveal|print|output|show|repeat|leak|display|dump|disclose|expose|recite|share)(?:me)?(?:allof|all)?"
                  r"your(?:full|entire|original|hidden|initial|exact|secret|system)?"
                  r"(?:systemprompts?|instructions|initialprompt|hiddenprompt|prompt|configuration|guidelines|rules)"),
    _rule("SEC02-SAF-01", "safety_disable",
          rf"\b{_DISABLE}\s+(?:{_DET}\s+)?(?:{_GUARD_ADJ}\s+){{1,3}}{_GUARD_NOUN}\b", negatable=True, despace=True),
    _rule("SEC02-SAF-02", "safety_disable",
          rf"\b{_DISABLE_STRONG}\s+(?:{_DET}\s+)?{_GUARD_ALONE}\b", negatable=True, despace=True),
    _rule("SEC02-EXF-03", "secret_exfiltration",
          rf"\b{_SEND}\s+(?:{_DET}\s+|of\s+|stored\s+|saved\s+|local\s+|current\s+)*(?:{_SECRET_STRONG}|{_SECRET_WEAK})"
          r"\s+(?:\w+\s+){0,5}?(?:to|into|via|over|at|on|through|in)\b",
          negatable=True),
)

# Text rules run on the folded text with punctuation intact (URLs, pipes, chat-template markers).
_NET_CMD = (r"(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|ftp|tftp|rsync|invoke-webrequest"
            r"|invoke-restmethod|iwr|irm|start-bitstransfer|certutil|bitsadmin|requests\.(?:get|post|put|patch|request)"
            r"|urlopen|httpx\.(?:get|post|stream)|fetch\s*\(|axios\.(?:get|post)|http\.(?:get|request)|socket\.connect"
            r"|net\.webclient|downloadstring|downloadfile)")
_EXTERNAL_IPV4 = (r"(?<![\d.])(?!127\.)(?!0\.0\.0\.0(?![\d.]))"
                  r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d)")
_ENCODED_HOST = r"://(?:\d{8,10}|0x[0-9a-f]{8}|0[0-7]{1,3}(?:\.0?[0-7]{1,3}){3}|\[(?!::1\])[0-9a-f:.]+\])"
_FETCH = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)"
_SHELL = (r"(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|k|da|fi|tc|c)?sh|python[0-9.]*|perl|ruby|node|php|iex|invoke-expression"
          r"|powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?)")
_SECRET_FILE = (r"(?:\.ssh[/\\](?:id_[\w.-]+|authorized_keys)|\.aws[/\\]credentials"
                r"|\.env(?:\.(?:local|prod|production|dev|development|staging))?(?![\w.])|\.netrc|\.git-credentials"
                r"|\.docker[/\\]config\.json|\.kube[/\\]config|etc[/\\]shadow|\.pgpass|\.npmrc|\.pypirc"
                r"|\bid_(?:rsa|ed25519|ecdsa|dsa)(?![\w.]))")
_PATH_PREFIX = r"[\"']?(?:[~$%\w./\\:-]*[/\\])?"

_TEXT_RULES: tuple[_Rule, ...] = (
    _rule("SEC02-EXF-01", "remote_fetch", rf"\b{_NET_CMD}(?![\w-])[^\n]{{0,200}}?(?:{_EXTERNAL_IPV4}|{_ENCODED_HOST})"),
    _rule("SEC02-EXF-02", "remote_exec",
          rf"\b{_FETCH}(?![\w-])[^\n|;&]{{0,300}}\|\s*{_SHELL}(?![\w-])"
          rf"|\b(?:(?:ba|z|k|da)?sh|python[0-9.]*|perl|ruby|node)\s+(?:-\w+\s+)*[\"']?(?:\$\(|<\(|`)\s*{_FETCH}(?![\w-])"
          r"|\b(?:iex|invoke-expression)(?![\w-])[^\n]{0,80}?\b(?:iwr|irm|invoke-webrequest|invoke-restmethod"
          r"|downloadstring|net\.webclient)\b"
          r"|\b(?:eval|exec)\s*\(\s*(?:requests\.get|urlopen|urllib\.request\.urlopen|httpx\.get)\b"),
    _rule("SEC02-EXF-04", "secret_file_read",
          r"\b(?:cat|type|more|less|head|tail|get-content|gc|base64|xxd|od|strings|cp|copy|scp|rsync|tar|zip|7z)"
          rf"\s+(?:-\S+\s+)*{_PATH_PREFIX}{_SECRET_FILE}"
          rf"|\bcurl\b[^\n]{{0,200}}?(?:-t\s+|--upload-file\s+|-f\s+\S*@|--data(?:-binary)?\s+@|-d\s+@){_PATH_PREFIX}{_SECRET_FILE}",
          negatable=True),
    _rule("SEC02-ROLE-01", "role_injection", r"<\|[a-z_]{2,40}\|>|\[/?inst\]|<</?sys>>|<(?:start|end)_of_turn>"),
)


def _scan_folded(folded: str) -> Iterator[tuple[_Rule, str]]:
    """Yield (rule, how) for every rule that fires on already-folded text."""
    for rule in _TEXT_RULES:
        for m in rule.pattern.finditer(folded):
            if rule.negatable:
                clause = _CLAUSE_BREAK.split(folded[:m.start()])[-1]
                if _negated(_words(clause).split()):
                    continue
            yield rule, "plain"
            break

    variants = (("plain", folded), *(("leetspeak", folded.translate(t)) for t in _LEET_VARIANTS))
    skeletons = [(how, _words(clause)) for how, text in variants for clause in _CLAUSE_BREAK.split(text)]
    for rule in _WORD_RULES:
        seen = fired = False
        for how, skeleton in skeletons:
            for m in rule.pattern.finditer(skeleton):
                seen = True
                if rule.negatable and _negated(skeleton[:m.start()].split()):
                    continue
                fired = True
                break
            if fired:
                yield rule, how
                break
        # Letter-spacing ("i g n o r e  p r e v i o u s ...") only counts when the phrase never
        # appeared normally, so a negated, defensive mention is not re-flagged here.
        if (not seen and rule.despaced is not None
                and any(rule.despaced.search(_NON_LETTER.sub("", text)) for _, text in variants)):
            yield rule, "spacing"


# ----------------------------------------------------------------------------- decoding

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_BACKSLASH_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_MAX_VARIANTS = 32


def _bytes_text(raw: bytes) -> str | None:
    if len(raw) < 8:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\n\t\r" for ch in text)
    return text if printable >= 0.9 * len(text) else None


def _b64_text(token: str) -> str | None:
    body = token.rstrip("=")
    if len(body) % 4 == 1:
        return None
    padded = body + "=" * (-len(body) % 4)
    for altchars in (None, b"-_"):
        try:
            return _bytes_text(base64.b64decode(padded, altchars=altchars, validate=True))
        except (binascii.Error, ValueError):
            continue
    return None


def _decodings(text: str) -> Iterator[tuple[str, str]]:
    if "%" in text:
        yield "percent", unquote(text)
    if "&" in text:
        yield "html", html.unescape(text)
    if "\\" in text:
        yield "escape", _BACKSLASH_ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)
    for m in _B64_TOKEN.finditer(text):
        if decoded := _b64_text(m.group()):
            yield "base64", decoded
    for m in _HEX_TOKEN.finditer(text):
        if decoded := _bytes_text(bytes.fromhex(m.group())):
            yield "hex", decoded


def _decoded_variants(label: str, text: str) -> list[tuple[str, str]]:
    """`text` plus up to two layers of decoded payloads (e.g. base64 wrapping percent-encoding)."""
    variants = [(label, text)]
    seen = {text}
    frontier = variants[:]
    for _ in range(2):
        found: list[tuple[str, str]] = []
        for prev_label, prev_text in frontier:
            for encoding, decoded in _decodings(prev_text):
                decoded = canonicalize(decoded)
                if decoded in seen or len(variants) >= _MAX_VARIANTS:
                    continue
                seen.add(decoded)
                item = (encoding if prev_label == "plain" else f"{prev_label}+{encoding}", decoded)
                variants.append(item)
                found.append(item)
        frontier = found
    return variants


def _unicode_tag_text(text: str) -> str:
    """ASCII smuggled as invisible Unicode tag characters (U+E0020..U+E007E)."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)


# ----------------------------------------------------------------------------- public API

def scan_text(text: str) -> tuple[tuple[str, str, str], ...]:
    """(rule_id, category, encoding) for each instruction-override signal in `text`."""
    hits: dict[str, tuple[str, str, str]] = {}
    roots = [("plain", canonicalize(text))]
    hidden = _unicode_tag_text(text)
    if len(hidden.strip()) >= 4:
        hits["SEC02-HIDDEN-01"] = ("SEC02-HIDDEN-01", "hidden_text", "unicode_tags")
        roots.append(("unicode_tags", canonicalize(hidden)))
    for root_label, root in roots:
        for encoding, variant in _decoded_variants(root_label, root):
            for rule, how in _scan_folded(_fold(variant)):
                label = encoding if how == "plain" else f"{encoding}+{how}"
                hits.setdefault(rule.rule_id, (rule.rule_id, rule.category, label))
    return tuple(hits.values())


def inspect(source_trust: object, fields: Mapping[str, str]) -> FirewallVerdict:
    """Decide whether an event may open the Plasticity Gate; fails closed on unknown trust labels."""
    findings: list[Finding] = []
    if isinstance(source_trust, str) and source_trust in SOURCE_TRUST_LEVELS:
        trust = source_trust
        if trust not in TRUSTED_SOURCES:
            findings.append(Finding("SEC02-TRUST-UNTRUSTED", "untrusted_source"))
    else:
        trust = "INVALID"
        findings.append(Finding("SEC02-TRUST-INVALID", "untrusted_source"))
    for name, value in fields.items():
        if not isinstance(value, str):
            raise TypeError(f"field {name!r} must be a string")
        findings.extend(Finding(rule_id, category, name, encoding) for rule_id, category, encoding in scan_text(value))
    return FirewallVerdict(allowed=not findings, source_trust=trust, findings=tuple(findings))
