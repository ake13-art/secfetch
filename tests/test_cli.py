"""Tests for CLI argument parsing and command routing."""
import threading
from unittest.mock import MagicMock, patch


class TestCLI:
    """Tests for CLI command routing."""

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.run_checks")
    @patch("secfesc.secfetch.cli.print_results")
    def test_default_runs_full_scan(self, mock_print, mock_run, mock_port_db):
        from secfesc.secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch"]):
            main()
        mock_run.assert_called_once_with(fast=False)
        mock_print.assert_called_once()

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.run_checks")
    @patch("secfesc.secfetch.cli.print_results_short")
    def test_short_flag(self, mock_print_short, mock_run, mock_port_db):
        from secfesc.secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "--short"]):
            main()
        mock_print_short.assert_called_once()

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.run_checks")
    @patch("secfesc.secfetch.cli.print_results")
    def test_fastscan(self, mock_print, mock_run, mock_port_db):
        from secfesc.secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "fastscan"]):
            main()
        mock_run.assert_called_once_with(fast=True)

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.print_help")
    def test_help_command(self, mock_help, mock_port_db):
        from secfesc.secfetch.cli import main
        with patch("sys.argv", ["secfetch", "help"]):
            main()
        mock_help.assert_called_once()

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.print_check_help")
    def test_help_specific_check(self, mock_check_help, mock_port_db):
        from secfesc.secfetch.cli import main
        with patch("sys.argv", ["secfetch", "help", "aslr"]):
            main()
        mock_check_help.assert_called_once_with("aslr")

    @patch("secfesc.secfetch.cli.port_db")
    def test_live_invalid_interval(self, mock_port_db, capsys):
        from secfesc.secfetch.cli import main
        with patch("sys.argv", ["secfetch", "live", "--interval", "0"]):
            main()
        captured = capsys.readouterr()
        assert "--interval must be at least 1" in captured.out

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.run_checks")
    @patch("secfesc.secfetch.cli.print_improve")
    def test_improve_command(self, mock_improve, mock_run, mock_port_db):
        from secfesc.secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "improve"]):
            main()
        mock_improve.assert_called_once()

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.run_checks")
    @patch("secfesc.secfetch.cli.apply_fixes")
    def test_improve_auto(self, mock_apply, mock_run, mock_port_db):
        from secfesc.secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "improve", "--auto"]):
            main()
        mock_apply.assert_called_once()

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.print_help")
    def test_dash_h_flag(self, mock_help, mock_port_db):
        from secfesc.secfetch.cli import main
        with patch("sys.argv", ["secfetch", "-h"]):
            main()
        mock_help.assert_called_once()

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.run_checks")
    @patch("secfesc.secfetch.cli.print_results_live", side_effect=KeyboardInterrupt)
    def test_live_command_exits_on_keyboard_interrupt(self, mock_live, mock_run, mock_port_db, capsys):
        from secfesc.secfetch.cli import main
        mock_run.return_value = []
        with patch("sys.argv", ["secfetch", "live"]):
            main()
        out = capsys.readouterr().out
        assert "stopped" in out.lower()

    @patch("secfesc.secfetch.cli.port_db")
    @patch("secfesc.secfetch.cli.run_checks")
    @patch("secfesc.secfetch.cli.print_results_live")
    def test_live_command_stop_event_wait_covered(self, mock_live, mock_run, mock_port_db, capsys):
        """Cover line 83: stop_event.wait() — needs one successful iteration before exit."""
        from secfesc.secfetch.cli import main
        mock_run.return_value = []

        def signal_stop(self_event, timeout=None):
            self_event.set()

        with patch("sys.argv", ["secfetch", "live"]), \
             patch("secfesc.secfetch.cli.threading.Thread") as MockThread, \
             patch.object(threading.Event, "wait", signal_stop):
            MockThread.return_value = MagicMock()
            main()

        out = capsys.readouterr().out
        assert "stopped" in out.lower()
        mock_live.assert_called_once()


class TestWaitForQuit:
    """Tests for _wait_for_quit() helper."""

    def test_non_tty_quit_on_q(self):
        import threading

        from secfesc.secfetch.cli import _wait_for_quit
        stop = threading.Event()
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with patch("builtins.input", side_effect=["q"]):
                _wait_for_quit(stop)
        assert stop.is_set()

    def test_non_tty_eof_exits_cleanly(self):
        import threading

        from secfesc.secfetch.cli import _wait_for_quit
        stop = threading.Event()
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with patch("builtins.input", side_effect=EOFError):
                _wait_for_quit(stop)
        assert not stop.is_set()

    def test_non_tty_ignores_non_q_input(self):
        import threading

        from secfesc.secfetch.cli import _wait_for_quit
        stop = threading.Event()
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with patch("builtins.input", side_effect=["x", "q"]):
                _wait_for_quit(stop)
        assert stop.is_set()
