import json

from quantasentry import cli


def test_cli_reports_a_missing_path_without_a_traceback(tmp_path, capsys):
    code = cli.main([str(tmp_path / "absent")])
    captured = capsys.readouterr()
    assert code == cli.EXIT_USAGE
    assert "quanta-sentry:" in captured.err
    assert "Traceback" not in captured.err


def test_cli_prints_a_json_report(tmp_path, capsys):
    (tmp_path / "app.py").write_text("key = RSA.generate(2048)\n")
    code = cli.main([str(tmp_path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_OK
    report = json.loads(captured.out)
    assert report["tool"] == "QuantaSentry"
    assert report["mode"] == "static-cryptographic-inventory"
    assert report["schema_version"] == 1
    assert report["findings"] == 1
    assert report["standard_references"] == ["FIPS 203", "FIPS 204", "FIPS 205"]
    assert "notice" in report


def test_cli_writes_the_report_to_the_output_path(tmp_path, capsys):
    (tmp_path / "app.py").write_text("key = RSA.generate(2048)\n")
    output = tmp_path / "report.json"
    code = cli.main([str(tmp_path), "--output", str(output)])
    capsys.readouterr()
    assert code == cli.EXIT_OK
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["findings"] == 1


def test_cli_reports_an_unwritable_output_path_without_a_traceback(tmp_path, capsys):
    (tmp_path / "app.py").write_text("key = RSA.generate(2048)\n")
    output = tmp_path / "missing-directory" / "report.json"
    code = cli.main([str(tmp_path), "--output", str(output)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_INVALID_INPUT
    assert "quanta-sentry:" in captured.err
    assert "Traceback" not in captured.err


def test_cli_fail_on_findings_returns_a_failing_status(tmp_path, capsys):
    (tmp_path / "app.py").write_text("key = RSA.generate(2048)\n")
    code = cli.main([str(tmp_path), "--fail-on-findings"])
    capsys.readouterr()
    assert code == cli.EXIT_INVALID_INPUT


def test_cli_fail_on_findings_succeeds_on_a_clean_tree(tmp_path, capsys):
    (tmp_path / "app.py").write_text("value = 1\n")
    code = cli.main([str(tmp_path), "--fail-on-findings"])
    capsys.readouterr()
    assert code == cli.EXIT_OK


def test_cli_accepts_a_single_file(tmp_path, capsys):
    target = tmp_path / "app.py"
    target.write_text("key = RSA.generate(2048)\n")
    code = cli.main([str(target)])
    report = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_OK
    assert report["findings"] == 1
