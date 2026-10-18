#!/usr/bin/env python3
"""Register a writer App via a local manifest flow, then configure CI."""

import argparse
import base64
import hmac
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import webbrowser


PERMISSIONS = {"contents": "write", "pull_requests": "write", "metadata": "read"}
ROOT = Path(__file__).resolve().parents[1]


def gh_api(endpoint, method="GET", payload=None, token=None):
    label = "App manifest conversion" if endpoint.startswith("app-manifests/") else endpoint.split("?")[0]
    if token:
        request = Request(
            f"https://api.github.com/{endpoint}",
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        try:
            with urlopen(request, timeout=30) as response:
                body = response.read()
        except (HTTPError, URLError):
            raise RuntimeError(f"GitHub {method} request failed for {label}; "
                               "check App permissions and installation.") from None
        return json.loads(body) if body else None
    args = ["gh", "api", endpoint, "--method", method]
    if payload is not None:
        args += ["--input", "-"]
    result = subprocess.run(
        args, input=json.dumps(payload) if payload is not None else None,
        text=True, capture_output=True,
    )
    if result.returncode:
        # API error bodies can contain credentials returned during conversion.
        raise RuntimeError(f"GitHub {method} request failed for {label}; "
                           "check authentication, permissions, and App installation.")
    return json.loads(result.stdout) if result.stdout.strip() else None


def manifest(owner, name, callback):
    return {
        "name": name,
        "url": f"https://github.com/{owner}/infra",
        "redirect_url": callback,
        "public": False,
        "default_permissions": PERMISSIONS,
        "default_events": [],
    }


def register(owner, owner_type, name):
    state = secrets.token_urlsafe(32)
    path = "/" + secrets.token_urlsafe(32)
    code = None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            nonlocal code
            parsed = urlparse(self.path)
            if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                self.send_error(400)
                return
            if parsed.path == path:
                destination = (f"https://github.com/organizations/{owner}/settings/apps/new"
                               if owner_type == "Organization"
                               else "https://github.com/settings/apps/new")
                callback = f"http://127.0.0.1:{self.server.server_port}/callback"
                body = (
                    '<form method="post" action="' + destination + '">'
                    '<input type="hidden" name="manifest" value="' +
                    html.escape(json.dumps(manifest(owner, name, callback)), quote=True) +
                    '"><input type="hidden" name="state" value="' + state +
                    '"><button>Create writer App on GitHub</button></form>'
                )
            elif parsed.path == "/callback":
                query = parse_qs(parsed.query)
                supplied_state = query.get("state", [""])[0]
                supplied_code = query.get("code", [""])[0]
                if not hmac.compare_digest(supplied_state, state) or not re.fullmatch(
                        r"[A-Za-z0-9_-]{1,256}", supplied_code):
                    self.send_error(400, "Invalid callback")
                    return
                code = supplied_code
                body = "Registration received. Return to the terminal."
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body.encode())

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        server.timeout = 1
        url = f"http://127.0.0.1:{server.server_port}{path}"
        print(f"Open locally (do not share): {url}")
        if not webbrowser.open(url):
            print("Browser could not be opened automatically; open the local URL above.")
        deadline = time.monotonic() + 600
        while code is None and time.monotonic() < deadline:
            server.handle_request()
        if code is None:
            raise RuntimeError("Registration timed out; no CI settings were written.")
    return gh_api(f"app-manifests/{code}/conversions", "POST", {})


def credential_path(directory):
    directory = directory.expanduser().resolve()
    if directory == ROOT or ROOT in directory.parents:
        raise RuntimeError("Credentials must be stored outside the repository.")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.stat().st_mode & 0o077:
        raise RuntimeError("Credentials directory must be private (chmod 700).")
    return directory / "writer-app.json"


def save_credentials(path, app, owner):
    if app.get("owner", {}).get("login", "").lower() != owner.lower():
        raise RuntimeError("Created App belongs to a different owner; no CI settings written.")
    if app.get("permissions") != PERMISSIONS or not app.get("pem", "").startswith(
            "-----BEGIN RSA PRIVATE KEY-----"):
        raise RuntimeError("App permissions or private key are invalid; no CI settings written.")
    with open(path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        json.dump(app, stream)
    print(f"Private recovery credentials saved at {path}; do not commit or share them.")


def app_jwt(app, directory):
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")

    now = int(time.time())
    data = encode(b'{"alg":"RS256","typ":"JWT"}') + b"." + encode(
        json.dumps({"iat": now - 60, "exp": now + 300, "iss": str(app["id"])}).encode())
    key = directory / ("key-" + secrets.token_hex(16) + ".pem")
    try:
        with open(key, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
            stream.write(app["pem"])
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key)],
            input=data, capture_output=True,
        )
        if result.returncode:
            raise RuntimeError("Could not sign App authentication token.")
        return (data + b"." + encode(result.stdout)).decode()
    finally:
        key.unlink(missing_ok=True)


def verify_installation(app, directory, owner, repo_id):
    jwt = app_jwt(app, directory)
    installation = gh_api(f"repos/{owner}/gitops/installation", token=jwt)
    if (installation.get("app_id") != app["id"]
            or installation.get("repository_selection") != "selected"
            or installation.get("permissions") != PERMISSIONS
            or installation.get("suspended_at")):
        raise RuntimeError("Install this writer App with its expected permissions on "
                           "selected repositories: gitops only.")
    access = gh_api(f"app/installations/{installation['id']}/access_tokens", "POST",
                    {"permissions": {"contents": "read"}}, token=jwt)
    token = access["token"]
    try:
        repos = gh_api("installation/repositories?per_page=100", token=token)
        if repos["total_count"] != 1 or repos["repositories"][0]["id"] != repo_id:
            raise RuntimeError("Writer App must be installed on gitops only.")
    finally:
        gh_api("installation/token", "DELETE", token=token)


def target_settings(owner):
    targets = []
    for name in ("backend", "frontend"):
        repo = f"{owner}/{name}"
        if not gh_api(f"repos/{repo}")["permissions"].get("admin"):
            raise RuntimeError(f"Repository admin permission required: {repo}")
        gh_api(f"repos/{repo}/environments/dev")
        variables = gh_api(f"repos/{repo}/environments/dev/variables?per_page=100")
        existing_id = next((row["value"] for row in variables["variables"]
                            if row["name"] == "GITOPS_APP_ID"), "")
        names = gh_api(f"repos/{repo}/environments/dev/secrets?per_page=100")
        existing_secret = any(row["name"] == "GITOPS_APP_PRIVATE_KEY"
                              for row in names["secrets"])
        if variables["total_count"] > 100 or names["total_count"] > 100:
            raise RuntimeError(f"Too many environment settings to verify safely: {repo}")
        targets.append((repo, existing_id, existing_secret))
    return targets


def configure(app, targets):
    for repo, existing_id, existing_secret in targets:
        if existing_id and existing_id != str(app["id"]):
            raise RuntimeError(f"{repo}/dev already references another writer App.")
        if existing_secret and not existing_id:
            raise RuntimeError(f"{repo}/dev has a key without a verifiable App ID.")
    print("Set writer App ID in backend/frontend dev; preserve existing matching keys.")
    if input("Write these GitHub environment settings? [y/N] ").lower() != "y":
        print("Cancelled; App and private recovery file retained, no CI settings written.")
        return
    for repo, _, existing_secret in targets:
        for args, value in [
            (["variable", "set", "GITOPS_APP_ID"], str(app["id"])),
            *([] if existing_secret else [
                (["secret", "set", "GITOPS_APP_PRIVATE_KEY"], app["pem"])]),
        ]:
            result = subprocess.run(
                ["gh", *args, "--repo", repo, "--env", "dev"],
                input=value, text=True, capture_output=True,
            )
            if result.returncode:
                raise RuntimeError(f"Setting write failed for {repo}/dev; partial writes "
                                   "may exist. Resume with the same recovery file.")
    for _, app_id, secret_exists in target_settings(app["owner"]["login"]):
        if app_id != str(app["id"]) or not secret_exists:
            raise RuntimeError("CI settings readback failed; inspect before retrying.")
    print("Writer setup verified. No workflows dispatched, commits pushed, or PRs merged.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default=os.environ.get("GITHUB_ORG"))
    parser.add_argument("--credentials-dir", type=Path, required=True,
                        help="Private recovery directory outside the repository (mode 700)")
    parser.add_argument("--resume", action="store_true",
                        help="Reuse saved credentials; do not create another App")
    options = parser.parse_args()
    if not options.owner or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", options.owner):
        raise RuntimeError("Provide --owner or GITHUB_ORG as a GitHub owner name.")
    for tool in ("gh", "openssl"):
        if subprocess.run(["which", tool], capture_output=True).returncode:
            raise RuntimeError(f"{tool} is required.")
    owner = gh_api(f"users/{options.owner}")
    if owner["type"] == "User" and gh_api("user")["login"].lower() != options.owner.lower():
        raise RuntimeError("Sign in as the personal account that will own the App.")
    repo_id = gh_api(f"repos/{options.owner}/gitops")["id"]
    targets = target_settings(options.owner)
    path = credential_path(options.credentials_dir)
    if options.resume:
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError("Recovery file must be private and not a symlink.")
        app = json.loads(path.read_text())
    else:
        if path.exists() or path.is_symlink():
            raise RuntimeError("Recovery file already exists; use --resume.")
        if any(app_id or key for _, app_id, key in targets):
            raise RuntimeError("Writer settings already exist; do not create a duplicate App.")
        print(f"Owner: {options.owner}; permissions: {PERMISSIONS}; install on gitops only.")
        if input("Create a new writer App through GitHub? [y/N] ").lower() != "y":
            print("Cancelled; no App or settings created.")
            return
        name = input("Unique writer App name: ").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 -]{0,99}", name):
            raise RuntimeError("Enter a nonempty App name using letters, numbers, spaces, hyphens.")
        app = register(options.owner, owner["type"], name)
        save_credentials(path, app, options.owner)
    if app.get("owner", {}).get("login", "").lower() != options.owner.lower():
        raise RuntimeError("Recovery App owner does not match requested owner.")
    if app.get("permissions") != PERMISSIONS:
        raise RuntimeError("Recovery App permissions do not match writer requirements.")
    print(f"Install this App on gitops only: https://github.com/apps/{app['slug']}/installations/new")
    input("Finish installation in GitHub, then press Enter to verify once: ")
    verify_installation(app, path.parent, options.owner, repo_id)
    configure(app, target_settings(options.owner))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, EOFError) as error:
        # Do not expose response bodies or credential-file content in exceptions.
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"Error: {message}. No automatic rollback; preserve recovery credentials "
              "and inspect App/settings before retrying.", file=sys.stderr)
        sys.exit(1)
