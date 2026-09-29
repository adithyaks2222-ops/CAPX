import sys
import pytest
from unittest.mock import patch
from capx.cli import main
from capx.config import config

def test_cli_help(capsys):
    with patch.object(sys, 'argv', ['capx.py', '--help']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
        captured = capsys.readouterr()
        assert "CAPX - Cyber Analysis & Protection eXplorer" in captured.out

def test_cli_version(capsys):
    with patch.object(sys, 'argv', ['capx.py', '--version']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 0
        captured = capsys.readouterr()
        assert "capx 0.1.0-alpha" in captured.out

def test_cli_inspect(capsys):
    with patch.object(sys, 'argv', ['capx.py', 'inspect']):
        main()
        captured = capsys.readouterr()
        assert "[*] Inspect command registered." in captured.out

def test_config_directories():
    config.setup_directories()
    assert config.LOG_DIR.exists()
    assert config.REPORT_DIR.exists()
    assert config.DATA_DIR.exists()