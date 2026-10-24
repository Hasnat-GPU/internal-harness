"""M1: Secure Event Ingestor & Normalizer (mod_ingest).

Every raw Harness² event passes, fail-closed, through:

1. validate   strict schema: unknown fields, bad enums, blank or oversized text -> EventRejected
2. clean      newlines normalised, invisible/control characters removed, NFC   (scrubber.clean_text)
3. SEC-01     secrets & PII -> <REDACTED_SECRET>                                (security/scrubber.py)
4. SEC-02     trust gate + instruction-override scan -> EventBlocked            (security/firewall.py)
5. tokenize   backbone chat format, <= 1024 tokens, every prompt position labelled -100

and leaves as a SanitizedEvent. A rejected or blocked event never produces one, so it can never
reach the Surprise Gate (M2). Semantic conflict detection (SOL-UNLEARN) needs backbone embeddings
and arrives with T06.
"""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, get_args

from pydantic import (
    UUID4,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from tokenizers import Tokenizer

from ..config import load_config, resolve_path
from ..security.firewall import FirewallVerdict, inspect
from ..security.scrubber import SecretScrubber, clean_text

DomainTag = Literal["prompt_refinement", "tool_synthesis", "memory_policy", "subagent_routing", "general"]
SourceTrust = Literal["HUMAN", "HARNESS2_VERIFIED", "UNTRUSTED_EXTERNAL"]
OutcomeStatus = Literal["VERIFIED_SUCCESS", "FAILURE"]
Flag = StrictBool | Literal[0, 1]  # JSON true/false or the blueprint's 0/1

DOMAIN_TAGS: tuple[str, ...] = get_args(DomainTag)
LABEL_MASK_ID = -100
DEFAULT_MAX_SEQ_LEN = 1024
DEFAULT_MAX_FIELD_CHARS = 32_000
DEFAULT_SYSTEM_PROMPT = "You are the Harness² Internal Harness policy memory. Domain: {domain_tag}."
DEFAULT_CHAT_FORMAT = {  # Qwen chat_template.jinja, non-thinking mode
    "system": "<|im_start|>system\n{system}<|im_end|>\n",
    "user": "<|im_start|>user\n{content}<|im_end|>\n",
    "assistant_prefix": "<|im_start|>assistant\n<think>\n\n</think>\n\n",
    "assistant_suffix": "<|im_end|>",
}


# ----------------------------------------------------------------------------- errors

class IngestError(Exception):
    """The event was not accepted; nothing from it reaches M2."""


class EventRejected(IngestError):
    """Schema validation failed (HTTP 422). Messages never echo input values."""

    def __init__(self, errors: list[dict[str, str]]) -> None:
        self.errors = errors
        super().__init__("; ".join(f"{e['loc']}: {e['msg']}" for e in errors))


class EventBlocked(IngestError):
    """SEC-02 blocked the event (HTTP 403). Carries rule ids and redaction counts, never text."""

    def __init__(self, verdict: FirewallVerdict, redaction_counts: Mapping[str, int]) -> None:
        self.verdict = verdict
        self.redaction_counts = dict(redaction_counts)
        super().__init__("blocked by SEC-02: " + ", ".join(verdict.rule_ids))


class TokenizerIntegrityError(RuntimeError):
    """tokenizer.json does not match the SHA-256 pinned in harness_config.yaml."""


def _safe_errors(exc: ValidationError, scrubber: SecretScrubber) -> list[dict[str, str]]:
    """Schema errors without input values (they may hold secrets); field paths are scrubbed too."""
    errors = []
    for err in exc.errors(include_url=False, include_context=False, include_input=False):
        loc = ".".join(str(part) for part in err["loc"]) or "<root>"
        msg = "Input should be a valid UUID v4" if err["type"].startswith("uuid") else err["msg"]
        errors.append({"loc": scrubber.scrub(loc).text, "type": err["type"], "msg": msg})
    return errors


# ----------------------------------------------------------------------------- input contract

class Harness2Event(BaseModel):
    """Raw event contract for ``POST /v1/observe``, validated before any security gate runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain_tag: DomainTag
    source_trust: SourceTrust
    outcome_status: OutcomeStatus
    context_text: StrictStr
    expected_action: StrictStr  # the verified action, or the failed action when outcome_status == "FAILURE"
    is_human_correction: Flag = False
    supersedes_previous: Flag = False
    supersedes_event_id: UUID4 | None = None
    verified_success_count: StrictInt = Field(default=1, ge=1)

    @field_validator("context_text", "expected_action")
    @classmethod
    def _bounded_text(cls, value: str, info: ValidationInfo) -> str:
        limit = (info.context or {}).get("max_field_chars", DEFAULT_MAX_FIELD_CHARS)
        if len(value) > limit:
            raise ValueError(f"must be at most {limit} characters")
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @model_validator(mode="after")
    def _human_correction_is_privileged(self) -> Harness2Event:
        # A human correction bypasses the surprise threshold and is auto-promoted to an anchor
        # (SOL-COLDSTART), so it must carry the highest trust level and a verified outcome.
        if self.is_human_correction and self.source_trust != "HUMAN":
            raise ValueError("is_human_correction requires source_trust='HUMAN'")
        if self.is_human_correction and self.outcome_status != "VERIFIED_SUCCESS":
            raise ValueError("is_human_correction requires outcome_status='VERIFIED_SUCCESS'")
        return self


# ----------------------------------------------------------------------------- output contract

@dataclass(frozen=True, slots=True)
class SanitizedEvent:
    """M1 output. Text fields are already scrubbed (SEC-01) and safe to persist."""

    # Blueprint M1 contract
    input_ids: tuple[int, ...]
    labels: tuple[int, ...]  # LABEL_MASK_ID on every prompt position: the loss only sees the action
    domain_tag: str
    outcome_status: str
    supersedes_id: str | None
    # episodic_events columns
    event_id: str
    created_at: int  # Unix epoch milliseconds
    source_trust: str
    is_human_correction: bool
    context_text: str
    expected_action: str
    supersedes_previous: bool
    verified_success_count: int
    # audit (T15 telemetry)
    redaction_counts: Mapping[str, int]
    context_tokens_dropped: int
    action_tokens_dropped: int

    @property
    def target_token_count(self) -> int:
        return sum(1 for label in self.labels if label != LABEL_MASK_ID)


# ----------------------------------------------------------------------------- tokenizer

_SPECIAL_MARKER = re.compile(r"(<\|[A-Za-z0-9_]+\|>)")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class EdgeTokenizer:
    """The backbone's ``tokenizer.json`` with special-token parsing disabled for event text.

    Event text is encoded with ``encode_special_tokens`` on, so a literal ``<|im_start|>`` typed
    into an event stays plain text. Chat-template markers become special tokens only when they come
    from the trusted template (:meth:`encode_template`).
    """

    def __init__(self, tokenizer: Tokenizer) -> None:
        tokenizer.encode_special_tokens = True
        self._tok = tokenizer
        self._special = {t.content: i for i, t in tokenizer.get_added_tokens_decoder().items() if t.special}

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any] | None = None) -> EdgeTokenizer:
        """Load ``tokenizer.json`` from ``weights/backbone`` (fetched from the pinned revision on first
        use) after checking its SHA-256."""
        cfg = cfg if cfg is not None else load_config()
        bb = cfg["backbone"]
        path = resolve_path(cfg["paths"]["backbone_dir"]) / bb["tokenizer_file"]
        if not path.is_file():
            if not bb.get("allow_download", False):
                raise FileNotFoundError(f"{path} is missing and backbone.allow_download is false")
            from huggingface_hub import hf_hub_download  # only needed on first run

            hf_hub_download(repo_id=bb["model_id"], filename=bb["tokenizer_file"], revision=bb["revision"],
                            local_dir=path.parent)
        expected = bb.get("tokenizer_sha256")
        if expected and _sha256(path) != expected:
            raise TokenizerIntegrityError(f"{path.name} does not match the SHA-256 pinned in harness_config.yaml")
        return cls(Tokenizer.from_file(str(path)))

    def encode_text(self, text: str) -> list[int]:
        """Encode event text; special-token strings inside it are split into ordinary tokens."""
        return self._tok.encode(text, add_special_tokens=False).ids if text else []

    def encode_template(self, template: str) -> list[int]:
        """Encode trusted template text; ``<|name|>`` markers map to their special-token ids."""
        ids: list[int] = []
        for piece in _SPECIAL_MARKER.split(template):
            if not piece:
                continue
            if _SPECIAL_MARKER.fullmatch(piece):
                if piece not in self._special:
                    raise ValueError(f"unknown special token {piece} in the chat template")
                ids.append(self._special[piece])
            else:
                ids.extend(self.encode_text(piece))
        return ids

    def special_id(self, token: str) -> int:
        return self._special[token]

    def decode(self, ids: Sequence[int], *, skip_special_tokens: bool = False) -> str:
        return self._tok.decode(list(ids), skip_special_tokens=skip_special_tokens)


# ----------------------------------------------------------------------------- normalizer

class Normalizer:
    """M1 pipeline: validate -> clean -> SEC-01 -> SEC-02 -> tokenize (see module docstring)."""

    def __init__(
        self,
        tokenizer: EdgeTokenizer,
        *,
        max_seq_len: int = DEFAULT_MAX_SEQ_LEN,
        max_field_chars: int = DEFAULT_MAX_FIELD_CHARS,
        min_context_tokens: int = 256,
        context_truncation: str = "left",
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        chat_format: Mapping[str, str] = DEFAULT_CHAT_FORMAT,
        scrubber: SecretScrubber | None = None,
    ) -> None:
        if context_truncation not in ("left", "right"):
            raise ValueError("context_truncation must be 'left' (keep the tail) or 'right' (keep the head)")
        self.tokenizer = tokenizer
        self.max_seq_len = max_seq_len
        self.max_field_chars = max_field_chars
        self.min_context_tokens = min_context_tokens
        self.context_truncation = context_truncation
        self.scrubber = scrubber or SecretScrubber()
        # The template never contains event text, so it is encoded once, with special tokens enabled.
        user_open, user_close = chat_format["user"].split("{content}")
        self._prefix_ids = {
            tag: tuple(tokenizer.encode_template(
                chat_format["system"].replace("{system}", system_prompt.replace("{domain_tag}", tag)) + user_open))
            for tag in DOMAIN_TAGS
        }
        self._bridge_ids = tuple(tokenizer.encode_template(user_close + chat_format["assistant_prefix"]))
        self._end_ids = tuple(tokenizer.encode_template(chat_format["assistant_suffix"]))
        overhead = max(map(len, self._prefix_ids.values())) + len(self._bridge_ids) + len(self._end_ids)
        if overhead + 2 > max_seq_len:
            raise ValueError(f"max_seq_len={max_seq_len} leaves no room after the {overhead}-token chat template")
        # Escaped JSON can need up to 6 bytes per character, for two text fields, plus the field names.
        self._max_raw_size = 2 * 6 * max_field_chars + 4096

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any] | None = None, *,
                    tokenizer: EdgeTokenizer | None = None) -> Normalizer:
        cfg = cfg if cfg is not None else load_config()
        ing = cfg["ingest"]
        for key, expected in (("domain_tags", DOMAIN_TAGS), ("source_trust_levels", get_args(SourceTrust)),
                              ("outcome_statuses", get_args(OutcomeStatus))):
            if tuple(ing[key]) != expected:
                raise ValueError(f"ingest.{key} in harness_config.yaml must equal {list(expected)}")
        return cls(
            tokenizer or EdgeTokenizer.from_config(cfg),
            max_seq_len=int(ing["max_seq_len"]),
            max_field_chars=int(ing["max_field_chars"]),
            min_context_tokens=int(ing["min_context_tokens"]),
            context_truncation=ing["context_truncation"],
            system_prompt=ing["system_prompt"],
            chat_format=cfg["backbone"]["chat_format"],
            scrubber=SecretScrubber.from_config(cfg),
        )

    def validate(self, raw: Mapping[str, Any] | str | bytes) -> Harness2Event:
        """Step 1: strict schema validation; raises EventRejected without echoing any input."""
        context = {"max_field_chars": self.max_field_chars}
        try:
            if isinstance(raw, (str, bytes, bytearray)):
                if len(raw) > self._max_raw_size:
                    raise EventRejected([{"loc": "<root>", "type": "too_large",
                                          "msg": f"payload exceeds {self._max_raw_size} bytes"}])
                return Harness2Event.model_validate_json(raw, context=context)
            return Harness2Event.model_validate(raw, context=context)
        except ValidationError as exc:
            raise EventRejected(_safe_errors(exc, self.scrubber)) from None  # the chained error holds the input

    def normalize(self, raw: Mapping[str, Any] | str | bytes, *, now_ms: int | None = None) -> SanitizedEvent:
        """Run the full M1 pipeline. Raises EventRejected / EventBlocked rather than return an unsafe event."""
        event = self.validate(raw)
        context = clean_text(event.context_text).strip()
        action = clean_text(event.expected_action).strip()
        for loc, text in (("context_text", context), ("expected_action", action)):
            if not text:  # e.g. a field made only of zero-width characters
                raise EventRejected([{"loc": loc, "type": "blank_after_cleaning", "msg": "contains no visible text"}])

        scrubbed_context = self.scrubber.scrub(context)  # SEC-01
        scrubbed_action = self.scrubber.scrub(action)
        redactions = Counter(scrubbed_context.counts_by_kind()) + Counter(scrubbed_action.counts_by_kind())

        verdict = inspect(event.source_trust, {"context_text": context, "expected_action": action})  # SEC-02
        if not verdict.allowed:
            raise EventBlocked(verdict, redactions)

        input_ids, labels, ctx_dropped, act_dropped = self._tokenize(
            event.domain_tag, scrubbed_context.text, scrubbed_action.text)
        return SanitizedEvent(
            input_ids=tuple(input_ids),
            labels=tuple(labels),
            domain_tag=event.domain_tag,
            outcome_status=event.outcome_status,
            supersedes_id=str(event.supersedes_event_id) if event.supersedes_event_id else None,
            event_id=str(uuid.uuid4()),
            created_at=now_ms if now_ms is not None else time.time_ns() // 1_000_000,
            source_trust=event.source_trust,
            is_human_correction=bool(event.is_human_correction),
            context_text=scrubbed_context.text,
            expected_action=scrubbed_action.text,
            supersedes_previous=bool(event.supersedes_previous) or event.supersedes_event_id is not None,
            verified_success_count=event.verified_success_count,
            redaction_counts=MappingProxyType(dict(redactions)),
            context_tokens_dropped=ctx_dropped,
            action_tokens_dropped=act_dropped,
        )

    def prompt_ids(self, domain_tag: str, context_text: str) -> list[int]:
        """Prompt for an already-sanitized context, ending at the assistant header (shared with M6/T07)."""
        return [*self._prefix_ids[domain_tag], *self.tokenizer.encode_text(context_text), *self._bridge_ids]

    def _tokenize(self, domain_tag: str, context: str, action: str) -> tuple[list[int], list[int], int, int]:
        prefix, bridge, end = self._prefix_ids[domain_tag], self._bridge_ids, self._end_ids
        ctx = self.tokenizer.encode_text(context)
        act = self.tokenizer.encode_text(action)
        budget = self.max_seq_len - len(prefix) - len(bridge) - len(end)
        # The action is the learning target: it keeps its tokens unless that would squeeze the context
        # below min_context_tokens, so an over-long context gives way first.
        act_keep = min(len(act), max(1, budget - min(len(ctx), self.min_context_tokens)))
        ctx_keep = min(len(ctx), budget - act_keep)
        kept_ctx = ctx[len(ctx) - ctx_keep:] if self.context_truncation == "left" else ctx[:ctx_keep]
        # A cut-off action gets no end-of-turn token, so the model never learns to stop mid-thought.
        target = [*act[:act_keep], *end] if act_keep == len(act) else act[:act_keep]
        prompt = [*prefix, *kept_ctx, *bridge]
        return [*prompt, *target], [LABEL_MASK_ID] * len(prompt) + target, len(ctx) - ctx_keep, len(act) - act_keep
