import io
import json
from pathlib import Path

from log_anonymizer.cli import main

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_cli_file_to_file(tmp_path):
    out = tmp_path / "out.log"
    assert main([str(SAMPLES / "app.log"), "-o", str(out)]) == 0
    text = out.read_text()
    for leak in ["192.168.1.42", "alice", "bob", "Sup3rS3cret", "jean.dupont", "06 12 34 56 78",
                 "00:1A:2B", "2001:db8", "+33 6", "abcdef1234567890"]:
        assert leak not in text
    assert len(text.splitlines()) == 7


def test_cli_jsonl(tmp_path):
    out = tmp_path / "out.jsonl"
    assert main([str(SAMPLES / "app.jsonl"), "-o", str(out), "-f", "json"]) == 0
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    assert rows[0]["user"] == "<USER>"
    assert rows[1]["password"] == "<SECRET>"
    assert rows[1]["client"]["email"] == "<EMAIL>"
    assert rows[2]["api_key"] == "<SECRET>"
    assert "0698765432" not in out.read_text()


def test_cli_stdin_stdout(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("ip 8.8.8.8\n"))
    assert main(["-p", "--salt", "x"]) == 0
    assert capsys.readouterr().out.startswith("ip <IPV4_")


def test_cli_custom_rules(tmp_path, capsys):
    f = tmp_path / "in.log"
    f.write_text("CMD-123456 by a@b.fr from 1.2.3.4\n")
    assert main([str(f), "--rules", str(SAMPLES / "custom_rules.json")]) == 0
    assert capsys.readouterr().out == "<ORDER> by <EMAIL> from 1.2.3.4\n"


def test_cli_bad_rules(tmp_path, capsys):
    assert main(["--rules", str(tmp_path / "missing.yaml")]) == 2
    assert "erreur" in capsys.readouterr().err


def test_cli_missing_input(tmp_path):
    assert main([str(tmp_path / "nope.log")]) == 1


def test_cli_invalid_json_strict(tmp_path):
    f = tmp_path / "in.jsonl"
    f.write_text("{bad\n")
    assert main([str(f), "-f", "json", "-o", str(tmp_path / "o")]) == 1
