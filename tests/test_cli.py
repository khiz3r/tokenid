import io
import json

from tokenid.cli import main


TOKEN = "550e8400-e29b-41d4-a716-446655440000"


def test_analyze_text_redacts_token(capsys):
    assert main(["analyze", TOKEN]) == 0
    out = capsys.readouterr().out
    assert "Token Pattern Analysis" in out
    assert TOKEN not in out
    assert "uuid_v4" in out


def test_analyze_json(capsys):
    assert main(["analyze", TOKEN, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "analysis"
    assert payload["token"] != TOKEN
    assert payload["candidates"][0]["token_type"] == "uuid_v4"


def test_show_token_opt_in(capsys):
    assert main(["analyze", TOKEN, "--show-token"]) == 0
    out = capsys.readouterr().out
    assert TOKEN in out


def test_decode_chain(capsys):
    assert main(["decode", "NDg2NTZjNmM2Zg=="]) == 0
    out = capsys.readouterr().out
    assert "base64" in out and "hex" in out
    assert "Hello" in out


def test_compare_file(capsys, tmp_path):
    path = tmp_path / "samples.txt"
    path.write_text("ID-0001\nID-0002\nID-0003\n", encoding="utf-8")
    assert main(["compare", str(path)]) == 0
    out = capsys.readouterr().out
    assert "Format: PREFIX + COUNTER" in out
    assert "Predictability: HIGH" in out


def test_batch_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(TOKEN + "\n"))
    assert main(["batch"]) == 0
    out = capsys.readouterr().out
    assert "uuid_v4" in out


def test_output_file(capsys, tmp_path):
    path = tmp_path / "report.json"
    assert main(["analyze", TOKEN, "--format", "json", "-o", str(path)]) == 0
    assert capsys.readouterr().out == ""
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["kind"] == "analysis"


def test_text_report_separates_sections(capsys):
    assert main(["analyze", TOKEN]) == 0
    out = capsys.readouterr().out
    assert "\n\nCandidates:" in out
    assert "\n\nEntropy:" in out
    assert "\n\nPredictability:" in out


def test_color_always_emits_ansi(capsys):
    assert main(["analyze", TOKEN, "--color", "always"]) == 0
    out = capsys.readouterr().out
    assert "\x1b[" in out


def test_color_never_emits_no_ansi(capsys):
    assert main(["analyze", TOKEN, "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "\x1b[" not in out
