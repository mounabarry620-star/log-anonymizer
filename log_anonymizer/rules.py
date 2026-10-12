"""Chargement des règles depuis un fichier YAML ou JSON."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .anonymizer import Anonymizer, Rule

DEFAULT_RULES_FILE = Path(__file__).with_name("default_rules.yaml")

_FLAGS = {"IGNORECASE": re.IGNORECASE, "I": re.IGNORECASE, "MULTILINE": re.MULTILINE, "M": re.MULTILINE}


def _read(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    import yaml  # import local : PyYAML n'est requis que pour les fichiers YAML

    return yaml.safe_load(text) or {}


def parse_config(config: dict[str, Any]) -> tuple[list[Rule], dict[str, str]]:
    """Transforme un dict de configuration en (règles, clés sensibles)."""
    rules = []
    for i, item in enumerate(config.get("rules", [])):
        if "pattern" not in item:
            raise ValueError(f"règle n°{i} : champ 'pattern' manquant")
        flags = 0
        for f in item.get("flags", []):
            try:
                flags |= _FLAGS[f.upper()]
            except KeyError:
                raise ValueError(f"règle n°{i} : flag inconnu {f!r}") from None
        name = item.get("name", f"rule{i}")
        try:
            rules.append(Rule(name=name, pattern=item["pattern"], label=item.get("label", name.upper()), flags=flags))
        except re.error as exc:
            raise ValueError(f"règle {name!r} : regex invalide ({exc})") from None
    return rules, _parse_keys(config.get("sensitive_keys", []))


def _parse_keys(raw: Any) -> dict[str, str]:
    """Accepte une liste de clés (label SECRET), un dict ou une liste mixte."""
    keys: dict[str, str] = {}
    items = raw.items() if isinstance(raw, dict) else raw
    for item in items:
        if isinstance(item, str):
            keys[item] = "SECRET"
        elif isinstance(item, dict):
            keys.update({str(k): str(v) for k, v in item.items()})
        else:
            k, v = item
            keys[str(k)] = str(v)
    return keys


def load_rules(path: str | Path | None = None) -> tuple[list[Rule], dict[str, str]]:
    return parse_config(_read(Path(path) if path else DEFAULT_RULES_FILE))


def default_rules() -> tuple[list[Rule], dict[str, str]]:
    return load_rules(None)


def build_anonymizer(path: str | Path | None = None, pseudonymize: bool = False, salt: str = "") -> Anonymizer:
    rules, keys = load_rules(path)
    return Anonymizer(rules, keys, pseudonymize=pseudonymize, salt=salt)
