"""Smoke tests for the top-level CLI."""

import subprocess
import sys

from typer.testing import CliRunner

from sherlog import __version__
from sherlog.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"sherlog {__version__}"


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output


def test_python_dash_m() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sherlog", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert __version__ in proc.stdout
