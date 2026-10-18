import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import threading
from urllib.error import HTTPError
from urllib.request import urlopen
from urllib.parse import urlparse
import re


SPEC = importlib.util.spec_from_file_location(
    "writer_app", Path(__file__).resolve().parents[1] / "00_setup_writer_app.py")
writer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(writer)


class WriterAppTests(unittest.TestCase):
    def app(self):
        return {"id": 123, "slug": "demo-writer", "owner": {"login": "demo"},
                "permissions": writer.PERMISSIONS,
                "pem": "-----BEGIN RSA PRIVATE KEY-----\nTEST-ONLY\n"}

    def test_manifest_is_portable_and_minimal(self):
        data = writer.manifest("demo", "demo-writer", "http://127.0.0.1:1234/callback")
        self.assertEqual(data["default_permissions"], writer.PERMISSIONS)
        self.assertFalse(data["public"])
        self.assertNotIn("hook_attributes", data)
        self.assertEqual(data["url"], "https://github.com/demo/infra")

    def test_local_manifest_callback_rejects_wrong_state(self):
        errors = []
        threads = []

        def open_browser(url):
            def browse():
                try:
                    with urlopen(url, timeout=5) as response:
                        page = response.read().decode()
                    state = re.search(r'name="state" value="([^"]+)"', page).group(1)
                    origin = "http://" + urlparse(url).netloc
                    with self.assertRaises(HTTPError) as error:
                        urlopen(origin + "/callback?state=wrong&code=test-code", timeout=5)
                    self.assertEqual(error.exception.code, 400)
                    with urlopen(origin + f"/callback?state={state}&code=test-code",
                                 timeout=5) as response:
                        self.assertEqual(response.status, 200)
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=browse)
            thread.start()
            threads.append(thread)
            return True

        with patch.object(writer.webbrowser, "open", side_effect=open_browser), \
                patch.object(writer, "gh_api", return_value=self.app()) as api, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(writer.register("demo", "User", "demo-writer"), self.app())
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse(errors)
        api.assert_called_once_with("app-manifests/test-code/conversions", "POST", {})

    def test_private_recovery_file_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = writer.credential_path(Path(directory))
            with contextlib.redirect_stdout(io.StringIO()):
                writer.save_credentials(path, self.app(), "demo")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text())["id"], 123)
            with self.assertRaises(FileExistsError):
                writer.save_credentials(path, self.app(), "demo")

    def test_reject_repository_and_public_directory(self):
        with self.assertRaises(RuntimeError):
            writer.credential_path(writer.ROOT / "credentials")
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(RuntimeError):
                writer.credential_path(Path(directory))

    def test_registration_owner_and_permissions_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.json"
            with self.assertRaises(RuntimeError):
                writer.save_credentials(path, self.app(), "someone-else")
            app = self.app()
            app["permissions"] = {"contents": "read"}
            with self.assertRaises(RuntimeError):
                writer.save_credentials(path, app, "demo")
            self.assertFalse(path.exists())

    def test_signing_failure_removes_temporary_key(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(writer.subprocess, "run",
                             return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaisesRegex(RuntimeError, "Could not sign"):
                writer.app_jwt(self.app(), Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cancel_writes_nothing(self):
        with patch("builtins.input", return_value="n"), \
                patch.object(writer.subprocess, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()):
            writer.configure(self.app(), [("demo/backend", "", False)])
        run.assert_not_called()

    def test_reject_existing_unrelated_credentials(self):
        for app_id, has_key in (("456", True), ("", True)):
            with self.subTest(app_id=app_id):
                with patch.object(writer.subprocess, "run") as run:
                    with self.assertRaises(RuntimeError):
                        writer.configure(self.app(), [("demo/backend", app_id, has_key)])
                run.assert_not_called()

    def test_write_key_via_stdin_and_preserve_matching_existing_key(self):
        targets = [("demo/backend", "", False), ("demo/frontend", "123", True)]
        with patch("builtins.input", return_value="y"), \
                patch.object(writer.subprocess, "run",
                             return_value=subprocess.CompletedProcess([], 0)) as run, \
                patch.object(writer, "target_settings",
                             return_value=[("demo/backend", "123", True),
                                           ("demo/frontend", "123", True)]), \
                contextlib.redirect_stdout(io.StringIO()):
            writer.configure(self.app(), targets)
        self.assertEqual(run.call_count, 3)
        key_call = run.call_args_list[1]
        self.assertEqual(key_call.kwargs["input"], self.app()["pem"])
        self.assertNotIn(self.app()["pem"], " ".join(key_call.args[0]))

    def test_api_errors_do_not_expose_response_or_conversion_code(self):
        with patch.object(writer.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 1, stdout="secret-response", stderr="secret-response")):
            with self.assertRaises(RuntimeError) as error:
                writer.gh_api("app-manifests/private-code/conversions", "POST", {})
        self.assertNotIn("private-code", str(error.exception))
        self.assertNotIn("secret-response", str(error.exception))

    def test_installation_only_gitops_and_token_revoked(self):
        installation = {"app_id": 123, "repository_selection": "selected",
                        "permissions": writer.PERMISSIONS, "id": 456}
        for count in (1, 2):
            with self.subTest(count=count), \
                    patch.object(writer, "app_jwt", return_value="test-jwt"), \
                    patch.object(writer, "gh_api", side_effect=[
                        installation, {"token": "test-token"},
                        {"total_count": count, "repositories": [{"id": 789}]}, None]) as api:
                if count == 1:
                    writer.verify_installation(self.app(), Path("/tmp"), "demo", 789)
                else:
                    with self.assertRaises(RuntimeError):
                        writer.verify_installation(self.app(), Path("/tmp"), "demo", 789)
                self.assertEqual(api.call_args.args, ("installation/token", "DELETE"))

    def test_failed_write_stops_without_printing_key(self):
        output = io.StringIO()
        with patch("builtins.input", return_value="y"), \
                patch.object(writer.subprocess, "run",
                             return_value=subprocess.CompletedProcess([], 1)), \
                contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError, "partial writes"):
                writer.configure(self.app(), [("demo/backend", "", False)])
        self.assertNotIn("TEST-ONLY", output.getvalue())


if __name__ == "__main__":
    unittest.main()
