import pytest

from log_anonymizer import Anonymizer
from log_anonymizer.rules import build_anonymizer, parse_config


@pytest.fixture
def anon():
    return build_anonymizer()


@pytest.mark.parametrize("text,expected", [
    ("from 192.168.1.42 port", "from <IPV4> port"),
    ("ip 2001:db8:85a3::8a2e:370:7334 ok", "ip <IPV6> ok"),
    ("ip ::1 ok", "ip <IPV6> ok"),
    ("ip fe80:0:0:0:200:f8ff:fe21:67cf", "ip <IPV6>"),
    ("mail jean.dupont@example.fr.", "mail <EMAIL>."),
    ("mac 00:1A:2B:3C:4D:5E", "mac <MAC>"),
    ("mac 00-1a-2b-3c-4d-5e", "mac <MAC>"),
    ("tel 06 12 34 56 78", "tel <PHONE>"),
    ("tel 06.12.34.56.78", "tel <PHONE>"),
    ("tel 0612345678", "tel <PHONE>"),
    ("tel +33 6 12 34 56 78", "tel <PHONE>"),
    ("tel 0033612345678", "tel <PHONE>"),
    ("password=hunter2 next", "password=<SECRET> next"),
    ("TOKEN: abc.def", "TOKEN: <SECRET>"),
    ('{"api_key": "k-1"} raw', '{"api_key": "<SECRET>"} raw'),
    ("Authorization: Bearer abcdef1234567890", "Authorization: Bearer <SECRET>"),
    ("user=alice action", "user=<USER> action"),
    ("Failed password for bob from", "Failed password for <USER> from"),
    ("Invalid login: carol", "Invalid login: <USER>"),
])
def test_default_rules(anon, text, expected):
    assert anon.anonymize_text(text) == expected


@pytest.mark.parametrize("text", [
    "version 1.2.3 build 2026-10-12",
    "duration 12:30:45",
    "999.1.1.1 is not an ip",
    "id 123456789012345",
    "retry for 5 seconds",
])
def test_no_false_positive(anon, text):
    assert anon.anonymize_text(text) == text


def test_invalid_regex():
    with pytest.raises(ValueError, match="regex invalide"):
        parse_config({"rules": [{"name": "bad", "pattern": "("}]})


def test_missing_pattern():
    with pytest.raises(ValueError, match="pattern"):
        parse_config({"rules": [{"name": "x"}]})


def test_unknown_flag():
    with pytest.raises(ValueError, match="flag"):
        parse_config({"rules": [{"pattern": "a", "flags": ["NOPE"]}]})


def test_custom_rules_json(tmp_path):
    f = tmp_path / "r.json"
    f.write_text('{"rules": [{"name": "order", "pattern": "CMD-\\\\d+"}]}')
    a = build_anonymizer(f)
    assert a.anonymize_text("cmd CMD-42 by 1.2.3.4") == "cmd <ORDER> by 1.2.3.4"


def test_custom_rules_yaml(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text("rules:\n  - name: id\n    label: ID\n    pattern: 'ID\\d+'\n")
    assert build_anonymizer(f).anonymize_text("x ID99") == "x <ID>"


def test_sensitive_keys_formats():
    _, keys = parse_config({"sensitive_keys": ["pwd", {"user": "USER"}]})
    assert keys == {"pwd": "SECRET", "user": "USER"}
    _, keys = parse_config({"sensitive_keys": {"mail": "EMAIL"}})
    assert keys == {"mail": "EMAIL"}
