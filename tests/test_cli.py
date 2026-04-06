"""Tests for CLI argument parsing and command routing."""
from unittest.mock import patch


class TestCLI:
    """Tests for CLI command routing."""

    @patch("secfetch.cli.port_db")
    @patch("secfetch.cli.run_checks")
    @patch("secfetch.cli.print_results")
    def test_default_runs_full_scan(self, mock_print, mock_run, mock_port_db):
        from secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch"]):
            main()
        mock_run.assert_called_once_with(fast=False)
        mock_print.assert_called_once()

    @patch("secfetch.cli.port_db")
    @patch("secfetch.cli.run_checks")
    @patch("secfetch.cli.print_results_short")
    def test_short_flag(self, mock_print_short, mock_run, mock_port_db):
        from secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "--short"]):
            main()
        mock_print_short.assert_called_once()

    @patch("secfetch.cli.port_db")
    @patch("secfetch.cli.run_checks")
    @patch("secfetch.cli.print_results")
    def test_fastscan(self, mock_print, mock_run, mock_port_db):
        from secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "fastscan"]):
            main()
        mock_run.assert_called_once_with(fast=True)

    @patch("secfetch.cli.port_db")
    @patch("secfetch.cli.print_help")
    def test_help_command(self, mock_help, mock_port_db):
        from secfetch.cli import main
        with patch("sys.argv", ["secfetch", "help"]):
            main()
        mock_help.assert_called_once()

    @patch("secfetch.cli.port_db")
    @patch("secfetch.cli.print_check_help")
    def test_help_specific_check(self, mock_check_help, mock_port_db):
        from secfetch.cli import main
        with patch("sys.argv", ["secfetch", "help", "aslr"]):
            main()
        mock_check_help.assert_called_once_with("aslr")

    @patch("secfetch.cli.port_db")
    def test_live_invalid_interval(self, mock_port_db, capsys):
        from secfetch.cli import main
        with patch("sys.argv", ["secfetch", "live", "--interval", "0"]):
            main()
        captured = capsys.readouterr()
        assert "--interval must be at least 1" in captured.out

    @patch("secfetch.cli.port_db")
    @patch("secfetch.cli.run_checks")
    @patch("secfetch.cli.print_improve")
    def test_improve_command(self, mock_improve, mock_run, mock_port_db):
        from secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "improve"]):
            main()
        mock_improve.assert_called_once()

    @patch("secfetch.cli.port_db")
    @patch("secfetch.cli.run_checks")
    @patch("secfetch.cli.apply_fixes")
    def test_improve_auto(self, mock_apply, mock_run, mock_port_db):
        from secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "improve", "--auto"]):
            main()
        mock_apply.assert_called_once()
