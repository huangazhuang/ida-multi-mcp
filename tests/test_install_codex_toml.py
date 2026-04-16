import os
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class TestInstallMcpServersCodexToml(unittest.TestCase):
    def test_windows_codex_config_remains_valid_toml(self):
        from ida_multi_mcp.__main__ import SERVER_NAME, install_mcp_servers

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_dir = home / ".codex"
            codex_dir.mkdir(parents=True, exist_ok=True)
            config_path = codex_dir / "config.toml"
            config_path.write_text(
                r"""
[projects.'\\?\C:\Git\MeroZemory\tidy-up']
trust_level = "trusted"

[model_reasoning_effort]
"gpt-5.2-codex" = "gpt-5.3-codex"
"gpt-5.2" = "gpt-5.3-codex"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            old_env = dict(os.environ)
            try:
                os.environ["HOME"] = str(home)
                os.environ["USERPROFILE"] = str(home)
                os.environ["APPDATA"] = str(home / "AppData" / "Roaming")

                with (
                    mock.patch("ida_multi_mcp.__main__.sys.platform", "win32"),
                    mock.patch("ida_multi_mcp.__main__.os.path.expanduser", return_value=str(home)),
                    mock.patch(
                        "ida_multi_mcp.__main__.get_python_executable",
                        return_value=r"C:\Users\MeroZemory\AppData\Local\Programs\Python\Python311\python.exe",
                    ),
                ):
                    install_mcp_servers(quiet=True)

                raw = config_path.read_text(encoding="utf-8")
                parsed = tomllib.loads(raw)

                self.assertEqual(
                    parsed["projects"][r"\\?\C:\Git\MeroZemory\tidy-up"]["trust_level"],
                    "trusted",
                )
                self.assertEqual(
                    parsed["mcp_servers"][SERVER_NAME]["command"],
                    r"C:\Users\MeroZemory\AppData\Local\Programs\Python\Python311\python.exe",
                )
                self.assertEqual(
                    parsed["mcp_servers"][SERVER_NAME]["args"],
                    ["-m", "ida_multi_mcp"],
                )
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
