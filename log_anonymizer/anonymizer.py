"""Moteur d'anonymisation : application de règles regex sur du texte ou du JSON."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator


@dataclass
class Rule:
    """Une règle de masquage.

    Si le motif contient un groupe nommé ``value``, seul ce groupe est masqué
    (utile pour ``password=secret`` : on garde ``password=``).
    """

    name: str
    pattern: str
    label: str
    flags: int = 0
    regex: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, self.flags)


class Anonymizer:
    """Applique des règles sur des lignes de logs.

    :param rules: règles regex appliquées dans l'ordre.
    :param sensitive_keys: clés JSON dont la valeur est masquée entièrement
        (liste -> label SECRET, ou dict clé -> label).
    :param pseudonymize: si vrai, une même valeur donne toujours le même jeton.
    :param salt: sel HMAC pour la pseudonymisation.
    """

    def __init__(
        self,
        rules: Iterable[Rule],
        sensitive_keys: Iterable[str] | dict[str, str] = (),
        pseudonymize: bool = False,
        salt: str = "",
    ) -> None:
        self.rules = list(rules)
        if not isinstance(sensitive_keys, dict):
            sensitive_keys = {k: "SECRET" for k in sensitive_keys}
        self.sensitive_keys = {k.lower(): v for k, v in sensitive_keys.items()}
        self.pseudonymize = pseudonymize
        self._salt = salt.encode("utf-8")

    # -- jetons -----------------------------------------------------------
    def token(self, label: str, value: str) -> str:
        if not self.pseudonymize:
            return f"<{label}>"
        digest = hmac.new(self._salt, f"{label}:{value}".encode("utf-8"), hashlib.sha256)
        return f"<{label}_{digest.hexdigest()[:8]}>"

    # -- texte ------------------------------------------------------------
    def anonymize_text(self, text: str) -> str:
        for rule in self.rules:
            text = rule.regex.sub(lambda m, r=rule: self._replace(m, r), text)
        return text

    def _replace(self, match: re.Match, rule: Rule) -> str:
        if "value" in match.re.groupindex and match.group("value") is not None:
            start, end = match.span("value")
            s0 = match.start()
            whole = match.group(0)
            value = match.group("value")
            if value.startswith("<") and value.endswith(">"):
                return whole  # déjà masqué
            return whole[: start - s0] + self.token(rule.label, value) + whole[end - s0 :]
        return self.token(rule.label, match.group(0))

    # -- JSON -------------------------------------------------------------
    def anonymize_obj(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for key, val in obj.items():
                if str(key).lower() in self.sensitive_keys and val is not None and not isinstance(val, (dict, list)):
                    out[key] = self.token(self.sensitive_keys[str(key).lower()], str(val))
                else:
                    out[key] = self.anonymize_obj(val)
            return out
        if isinstance(obj, list):
            return [self.anonymize_obj(v) for v in obj]
        if isinstance(obj, str):
            return self.anonymize_text(obj)
        return obj

    def anonymize_line(self, line: str, fmt: str = "auto") -> str:
        """Anonymise une ligne. ``fmt`` vaut ``auto``, ``text`` ou ``json``."""
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        if fmt in ("auto", "json") and body.lstrip().startswith(("{", "[")):
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                if fmt == "json":
                    raise
            else:
                return json.dumps(self.anonymize_obj(data), ensure_ascii=False) + newline
        return self.anonymize_text(body) + newline

    def anonymize_lines(self, lines: Iterable[str], fmt: str = "auto") -> Iterator[str]:
        for line in lines:
            yield self.anonymize_line(line, fmt)
