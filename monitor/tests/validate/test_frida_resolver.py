"""Tests for FridaResolver capability and macOS permission diagnostics."""

import sys
import platform
import unittest
from unittest.mock import MagicMock, patch

from monitor.instrumentation.frida.frida_resolver import FridaResolution, FridaResolver


class TestFridaResolver(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = FridaResolver()

    @patch.dict("sys.modules", {"frida": None})
    @patch("shutil.which")
    def test_frida_not_installed(self, mock_which: MagicMock) -> None:
        # Simulate ImportError
        mock_which.return_value = None

        res = self.resolver.resolve()
        self.assertFalse(res.import_ok)
        self.assertFalse(res.package_available)
        self.assertFalse(res.attach_ready)
        self.assertIn("frida_import_failed", res.warnings)

    @patch("monitor.instrumentation.frida.frida_resolver.inspect.getfile")
    @patch("shutil.which")
    def test_frida_shadowed_by_local_dir(self, mock_which: MagicMock, mock_getfile: MagicMock) -> None:
        mock_which.return_value = "/usr/local/monitor/bin/frida-ps"
        
        # Mock frida module as an empty object representing the namespace
        frida_mock = MagicMock()
        del frida_mock.attach
        del frida_mock.get_local_device
        
        with patch.dict("sys.modules", {"frida": frida_mock}):
            # Simulate a local path that would trigger shadowing
            mock_getfile.side_effect = TypeError("<module 'frida' (namespace)> is a built-in module")
            
            res = self.resolver.resolve()
            
            self.assertTrue(res.import_ok)
            self.assertTrue(res.shadowed)
            self.assertFalse(res.package_available)
            self.assertIn("frida_import_shadowed", res.warnings)

    @patch("monitor.instrumentation.frida.frida_resolver.inspect.getfile")
    @patch("shutil.which")
    def test_frida_properly_installed_but_cli_missing(self, mock_which: MagicMock, mock_getfile: MagicMock) -> None:
        mock_which.return_value = None
        mock_getfile.return_value = "/usr/lib/python3.9/site-packages/frida/__init__.py"
        
        frida_mock = MagicMock()
        frida_mock.__version__ = "16.1.4"
        frida_mock.attach = MagicMock()
        device_mock = MagicMock()
        frida_mock.get_local_device.return_value = device_mock

        with patch.dict("sys.modules", {"frida": frida_mock}):
            with patch("monitor.instrumentation.frida.frida_resolver.sys.executable", "/tmp/no-frida-env/monitor/bin/python"):
                res = self.resolver.resolve()
            self.assertTrue(res.import_ok)
            self.assertFalse(res.shadowed)
            self.assertTrue(res.package_available)
            self.assertTrue(res.attach_ready)
            self.assertIn("frida_cli_tools_not_on_path", res.warnings)

    @patch("platform.machine")
    @patch("platform.system")
    @patch("monitor.instrumentation.frida.frida_resolver.FridaResolver._system_arch")
    @patch("shutil.which")
    def test_apple_silicon_warns_when_python_runs_under_rosetta(
        self,
        mock_which: MagicMock,
        mock_system_arch: MagicMock,
        mock_system: MagicMock,
        mock_machine: MagicMock,
    ) -> None:
        mock_which.return_value = None
        mock_system.return_value = "Darwin"
        mock_machine.return_value = "x86_64"
        mock_system_arch.return_value = "arm64"

        with patch.dict("sys.modules", {"frida": None}):
            res = self.resolver.resolve()

        self.assertTrue(res.arch_mismatch)
        self.assertEqual(res.python_arch, "x86_64")
        self.assertEqual(res.system_arch, "arm64")
        self.assertIn("frida_python_arch_mismatch", res.warnings)
        self.assertIn("arm64 Python", res.install_hint or "")

    @patch("platform.system")
    @patch("monitor.instrumentation.frida.frida_resolver.inspect.getfile")
    @patch("shutil.which")
    def test_macos_task_for_pid_blocked(self, mock_which: MagicMock, mock_getfile: MagicMock, mock_system: MagicMock) -> None:
        mock_system.return_value = "Darwin"
        mock_which.return_value = "/usr/local/monitor/bin/frida-ps"
        mock_getfile.return_value = "/usr/lib/python3.9/site-packages/frida/__init__.py"
        
        frida_mock = MagicMock()
        # attach to self fails due to task_for_pid
        frida_mock.attach.side_effect = Exception("unable to access process with pid 12345 from the current user account: task_for_pid() not permitted")
        frida_mock.get_local_device.return_value.enumerate_processes.return_value = []

        with patch.dict("sys.modules", {"frida": frida_mock}):
            res = self.resolver.resolve(self_attach_check=True)
            self.assertTrue(res.package_available)
            self.assertFalse(res.attach_ready)
            self.assertTrue(res.permission_status.task_for_pid_likely_blocked)
            self.assertFalse(res.permission_status.can_attach_self)
            self.assertIn("frida_task_for_pid_permission_required", res.warnings)

    @patch("platform.system")
    @patch("monitor.instrumentation.frida.frida_resolver.inspect.getfile")
    @patch("shutil.which")
    def test_macos_sip_blocked(self, mock_which: MagicMock, mock_getfile: MagicMock, mock_system: MagicMock) -> None:
        mock_system.return_value = "Darwin"
        mock_which.return_value = "/usr/local/monitor/bin/frida-ps"
        mock_getfile.return_value = "/usr/lib/python3.9/site-packages/frida/__init__.py"
        
        frida_mock = MagicMock()
        frida_mock.attach.side_effect = Exception("system integrity protection is enabled")
        frida_mock.get_local_device.return_value.enumerate_processes.return_value = []

        with patch.dict("sys.modules", {"frida": frida_mock}):
            res = self.resolver.resolve(self_attach_check=True)
            self.assertTrue(res.package_available)
            self.assertFalse(res.attach_ready)
            self.assertTrue(res.permission_status.sip_maybe_related)
            self.assertIn("frida_sip_maybe_blocking", res.warnings)


if __name__ == "__main__":
    unittest.main()
