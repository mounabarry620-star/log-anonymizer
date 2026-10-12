import json

from log_anonymizer.rules import build_anonymizer


def test_pseudonymize_consistent():
    a = build_anonymizer(pseudonymize=True, salt="s")
    out1 = a.anonymize_text("a 10.0.0.1 b 10.0.0.2 c 10.0.0.1")
    toks = out1.split()[1::2]
    assert toks[0] == toks[2] != toks[1]
    assert toks[0].startswith("<IPV4_")
    # même valeur dans un autre appel -> même jeton
    assert a.anonymize_text("10.0.0.1") == toks[0]


def test_salt_changes_tokens():
    a = build_anonymizer(pseudonymize=True, salt="a")
    b = build_anonymizer(pseudonymize=True, salt="b")
    assert a.anonymize_text("x@y.fr") != b.anonymize_text("x@y.fr")


def test_json_line():
    a = build_anonymizer()
    line = json.dumps({"user": "alice", "password": "p", "nested": {"email": "a@b.fr", "n": 3},
                       "list": ["1.2.3.4"], "msg": "from 10.0.0.1"}) + "\n"
    out = a.anonymize_line(line)
    assert out.endswith("\n")
    data = json.loads(out)
    assert data["password"] == "<SECRET>"
    assert data["nested"] == {"email": "<EMAIL>", "n": 3}
    assert data["list"] == ["<IPV4>"]
    assert data["msg"] == "from <IPV4>"


def test_json_pseudonymized_secret_consistent():
    a = build_anonymizer(pseudonymize=True)
    o1 = json.loads(a.anonymize_line('{"token": "abc"}'))
    o2 = json.loads(a.anonymize_line('{"token": "abc"}'))
    assert o1 == o2 and o1["token"].startswith("<SECRET_")


def test_auto_falls_back_to_text_on_invalid_json():
    a = build_anonymizer()
    assert a.anonymize_line("{not json 1.2.3.4") == "{not json <IPV4>"


def test_text_format_forced():
    a = build_anonymizer()
    out = a.anonymize_line('{"ip": "1.2.3.4"}', fmt="text")
    assert out == '{"ip": "<IPV4>"}'
