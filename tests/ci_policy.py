#!/usr/bin/env python3
"""Choose the smallest system suite that covers a pull request's changed files."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

CRITICAL = {
    "veiltrium.sh", "tools/keenetic-vpn-probe.sh",
    ".github/workflows/panel-release.yml",
}
CI_WORKFLOWS = {
    ".github/workflows/fast.yml", ".github/workflows/e2e.yml",
    ".github/workflows/integration.yml", ".github/actionlint.yaml",
}
FAST_TESTS = {"tests/fast.sh", "tests/unit.sh", "tests/ci_policy.py", "tests/test_ci_policy.py"}


def risk(path):
    if path in CRITICAL:
        return "full"
    if path in CI_WORKFLOWS:
        return "integration"
    if path.startswith("tests/browser/") or path.startswith("panel/web/"):
        return "fast"
    if path.startswith("panel/") or path in {
        "tests/clients-ci.sh", "tests/panel-ci.sh", "tests/features-ci.sh",
        "tests/reselect-ci.sh", "tests/probe-ci.sh", "tests/longconn.sh",
        "tests/sites-setup.sh", "tests/release-panel-ci.sh"
    }:
        return "integration"
    if path in FAST_TESTS or (path.startswith("tests/unit-") and path.endswith(".sh")):
        return "fast"
    if path.endswith(".md") or path in {"LICENSE", ".gitignore", ".gitattributes"}:
        return "fast"
    # Unknown executable/build paths are conservative, including deletions and renames.
    return "full"


def plan(paths, draft=False):
    levels = {risk(path) for path in paths}
    required = "full" if "full" in levels else "integration" if "integration" in levels else "fast"
    selected = "integration" if required == "full" and draft else required
    return {"profile": selected, "full_required": required == "full", "release_panel": False,
            "reason": "FULL deferred until Ready for review" if selected != required else f"Changed files require {required.upper()}"}


def changed_files(base, head):
    # Workflow values are commit ids, never shell commands or git options.
    if not all(re.fullmatch(r"[0-9a-f]{40,64}", value) for value in (base, head)):
        raise ValueError("base and head must be full commit ids")
    raw = subprocess.check_output([
        "git", "diff", "--name-only", "--no-renames", "-z", f"{base}...{head}", "--"
    ])
    return [p.decode("utf-8", errors="surrogateescape") for p in raw.split(b"\0") if p]


def installer_metadata(text):
    return dict(re.findall(
        r'^(SCRIPT_VERSION|PANEL_VERSION|PANEL_SHA256_AMD64|PANEL_SHA256_ARM64)="([^"]*)"$',
        text, re.MULTILINE))


def release_metadata_changed(base, head):
    metadata = []
    for revision in (base, head):
        result = subprocess.run(["git", "show", f"{revision}:veiltrium.sh"],
                                capture_output=True, text=True, check=False)
        metadata.append(installer_metadata(result.stdout))
    return all(len(fields) == 4 for fields in metadata) and metadata[0] != metadata[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument("--draft", choices=("true", "false"), default="false")
    parser.add_argument("--manual", choices=("integration", "full"))
    parser.add_argument("--release-panel", action="store_true")
    args = parser.parse_args()
    result = ({"profile": args.manual, "full_required": args.manual == "full", "release_panel": args.release_panel, "reason": "Manual selection"}
              if args.manual else plan(changed_files(args.base, args.head), args.draft == "true"))
    if not args.manual and result["profile"] == "full":
        result["release_panel"] = release_metadata_changed(args.base, args.head)
        if result["release_panel"]:
            result["reason"] += "; final version/pins select published panel"
    print(json.dumps(result))
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as f:
            for key, value in result.items():
                f.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as f:
            f.write(f"### CI plan\n\n**{result['profile'].upper()}** — {result['reason']}.\n")


if __name__ == "__main__":
    main()
