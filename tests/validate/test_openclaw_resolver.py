"""Tests for the OpenClaw Binary Resolver."""

import os
import platform
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from app.runtime.agent_scenarios.openclaw_resolver import OpenClawResolver


class TestOpenClawResolver(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = OpenClawResolver(min_version="2026.4.24")

    @patch("app.runtime.agent_scenarios.openclaw_resolver.subprocess.run")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.os.access")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.Path.exists")
    @patch("shutil.which")
    def test_resolve_success_from_path(self, mock_which: MagicMock, mock_exists: MagicMock, mock_access: MagicMock, mock_run: MagicMock) -> None:
        # Mock PATH resolution
        mock_which.return_value = "/usr/bin/openclaw"
        
        # Mock valid file existence and execution permission
        mock_exists.return_value = True
        mock_access.return_value = True

        # Mock openclaw --version
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "OpenClaw v2026.5.0\n"
        mock_run.return_value = mock_proc

        with patch.dict(os.environ, {}, clear=True):
            res = self.resolver.resolve()
            
            self.assertIsNotNone(res.selected_candidate)
            self.assertEqual(res.selected_candidate.path, "/usr/bin/openclaw")
            self.assertEqual(res.selected_candidate.source, "path")
            self.assertEqual(res.selected_candidate.parsed_version, "2026.5.0")
            self.assertTrue(res.selected_candidate.ok)

    @patch("app.runtime.agent_scenarios.openclaw_resolver.subprocess.run")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.os.access")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.Path.exists")
    @patch("shutil.which")
    def test_version_too_low(self, mock_which: MagicMock, mock_exists: MagicMock, mock_access: MagicMock, mock_run: MagicMock) -> None:
        mock_which.return_value = "/usr/bin/openclaw"
        mock_exists.return_value = True
        mock_access.return_value = True

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "OpenClaw v2025.1.1\n"
        mock_run.return_value = mock_proc

        with patch.dict(os.environ, {}, clear=True):
            res = self.resolver.resolve()
            
            self.assertIsNone(res.selected_candidate)
            self.assertIn("No valid OpenClaw binary found.", res.errors)
            self.assertEqual(res.candidates[0].reason, "Version 2025.1.1 < 2026.4.24")

    @patch("app.runtime.agent_scenarios.openclaw_resolver.subprocess.run")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.os.access")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.Path.exists")
    @patch("shutil.which")
    def test_env_var_priority(self, mock_which: MagicMock, mock_exists: MagicMock, mock_access: MagicMock, mock_run: MagicMock) -> None:
        mock_which.return_value = "/usr/bin/openclaw"
        mock_exists.return_value = True
        mock_access.return_value = True

        def mock_run_side_effect(args, **kwargs):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            if "/custom/openclaw" in args[0]:
                mock_proc.stdout = "2026.10.1"
            else:
                mock_proc.stdout = "2026.5.0"
            return mock_proc

        mock_run.side_effect = mock_run_side_effect

        with patch.dict(os.environ, {"OPENCLAW_BIN": "/custom/openclaw"}, clear=True):
            res = self.resolver.resolve()
            
            self.assertIsNotNone(res.selected_candidate)
            # Both meet min version, but we expect the higher version or the first one checked to be selected based on sort logic.
            # 2026.10.1 > 2026.5.0, so the custom one should win.
            self.assertEqual(res.selected_candidate.path, "/custom/openclaw")
            self.assertEqual(res.selected_candidate.source, "env")

    @patch("app.runtime.agent_scenarios.openclaw_resolver.subprocess.run")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.os.access")
    @patch("app.runtime.agent_scenarios.openclaw_resolver.Path.exists")
    @patch("shutil.which")
    def test_no_valid_binary_falls_back_gracefully(self, mock_which: MagicMock, mock_exists: MagicMock, mock_access: MagicMock, mock_run: MagicMock) -> None:
        mock_which.return_value = None
        mock_exists.return_value = False

        res = self.resolver.resolve()
        
        self.assertIsNone(res.selected_candidate)
        self.assertIn("No valid OpenClaw binary found.", res.errors)

if __name__ == "__main__":
    unittest.main()
