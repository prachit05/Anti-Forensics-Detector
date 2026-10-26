"""Smoke test of the Streamlit dashboard with Streamlit's own test runner (no browser)."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit.testing.v1")
from streamlit.testing.v1 import AppTest

from tests.test_pipeline_reporting import _tampered_entries
from tests.mft_builder import write_mft

APP = str(Path(__file__).resolve().parents[1] / "app.py")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AFD_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("AFD_EVIDENCE_DIR", str(tmp_path / "evidence"))
    art = tmp_path / "evidence" / "artifacts"
    art.mkdir(parents=True)
    write_mft(art / "$MFT", _tampered_entries())
    return art


def test_dashboard_runs_analysis_and_writes_report(env):
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception

    at.sidebar.text_input[1].set_value(str(env))          # source
    at.sidebar.text_input[2].set_value("ui_case")         # case name
    at.sidebar.button[0].click().run()
    assert not at.exception
    assert at.header[0].value == "Case: ui_case"
    assert [m.label for m in at.metric][:3] == ["HIGH", "MEDIUM", "LOW"]

    at.text_area[0].set_value("Examiner wrote this.")
    next(b for b in at.button if b.label.startswith("Generate")).click().run()
    assert not at.exception
    html = (Path(env).parents[1] / "cases" / "ui_case" / "report.html").read_text(encoding="utf-8")
    assert "Examiner wrote this." in html


def test_dashboard_reopens_saved_case(env):
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.sidebar.text_input[1].set_value(str(env))
    at.sidebar.text_input[2].set_value("saved_case")
    at.sidebar.button[0].click().run()

    at2 = AppTest.from_file(APP, default_timeout=60).run()
    at2.sidebar.radio[0].set_value("Open saved case").run()
    at2.sidebar.button[0].click().run()
    assert not at2.exception
    assert at2.header[0].value == "Case: saved_case"
    next(b for b in at2.button if b.label == "Re-verify evidence hashes").click().run()
    assert not at2.exception
    assert any("still match" in s.value for s in at2.success)


def test_nothing_analysed_is_a_warning_not_a_clean_result(tmp_path, monkeypatch):
    """A folder holding only a disk image: every detector is skipped. That must not show
    the green 'No findings' box (seen when the evidence folder itself was given as input)."""
    monkeypatch.setenv("AFD_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("AFD_EVIDENCE_DIR", str(tmp_path / "evidence"))
    folder = tmp_path / "evidence" / "images"
    folder.mkdir(parents=True)
    (folder / "disk.vhd").write_bytes(b"\x00" * 4096)
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.sidebar.text_input[1].set_value(str(folder.parent))
    at.sidebar.text_input[2].set_value("empty_case")
    at.sidebar.button[0].click().run()
    assert not at.exception
    assert any("Nothing was analysed" in w.value for w in at.warning)
    assert not any("No findings" in s.value for s in at.success)
