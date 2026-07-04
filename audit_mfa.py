#!/usr/bin/env python3
"""
Audit Salesforce MFA readiness for a CLI-authenticated org alias.

This script focuses on the June/July 2026 MFA controls that can be verified
from org metadata and SOQL-accessible configuration:

1. MFA for all direct UI logins.
2. Phishing-resistant MFA readiness for privileged users.
3. Bypass / waiver assignments that can undermine compliance.
4. SSO presence that requires separate IdP AMR/ACR validation.

It intentionally reports some items as "manual review required" because the
relevant enrollment/signal data isn't fully exposed through standard sf CLI
query surfaces.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import html
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


API_VERSION = "66.0"
NAMESPACE = {"md": "http://soap.sforce.com/2006/04/metadata"}
# Minimum known-good Salesforce CLI version. The script relies on `sf` v2
# command syntax (e.g. `sf data query`, `sf org display`), which requires the
# v2 CLI; older sfdx-era releases do not ship the `sf` executable used here.
MIN_SF_CLI_VERSION = (2, 0, 0)
USER_QUERY_LIMIT = 250
USER_RENDER_LIMIT = 50
PRIVILEGED_PERMISSION_FIELDS = {
    "PermissionsModifyAllData": "Modify All Data",
    "PermissionsViewAllData": "View All Data",
    "PermissionsCustomizeApplication": "Customize Application",
    "PermissionsAuthorApex": "Author Apex",
}
EXTERNAL_USER_TYPE_KEYWORDS = (
    "guest",
    "portal",
    "partner",
    "community",
    "external",
    "powerpartner",
    "selfservice",
    "csp",
)
NON_INTERACTIVE_USER_TYPES = {"AutomatedProcess"}
INTERNAL_LICENSE_EXCLUSIONS = {
    "Guest",
    "Customer Community",
    "Customer Community Login",
    "External Apps",
    "External Identity",
    "High Volume Customer Portal",
}
PHISHING_RESISTANT_AMR_CODES = {
    "cert",
    "fido",
    "fido2",
    "fpt",
    "hwk",
    "iris",
    "pin",
    "pki",
    "pop",
    "retina",
    "sc",
    "smartcard",
    "swk",
    "tlsclient",
    "user",
    "vbm",
    "wia",
    "x509",
}
STANDARD_MFA_AMR_CODES = {
    "face",
    "mfa",
    "mobiletwofactorcontract",
    "multipleauthn",
    "okta_verify",
    "passkey",
    "webauthn",
}
WEAK_OR_NO_MFA_AMR_CODES = {"email", "pwd", "sms", "tel"}
ACR_LOGIN_HISTORY_FIELD_CANDIDATES = (
    "AcrContextClassReference",
    "AuthnContextClassRef",
    "AcrReference",
    "Acr",
)
USER_SELECT_FIELDS = textwrap.dedent(
    """
    Id, Name, Username, UserType, IsActive, IsPortalEnabled,
    Profile.Name, Profile.UserLicense.Name,
    Profile.PermissionsModifyAllData, Profile.PermissionsViewAllData,
    Profile.PermissionsCustomizeApplication, Profile.PermissionsAuthorApex,
    Profile.PermissionsForceTwoFactor, Profile.PermissionsBypassMFAForUiLogins
    """
).strip()
VERIFICATION_METHOD_LABELS = {
    "Totp": "One-time password",
    "Sms": "Text message",
    "Email": "Email message",
    "SalesforceAuthenticator": "Salesforce Authenticator",
    "TempCode": "Temporary code",
    "U2F": "U2F security key",
    "LL": "Lightning Login",
    "EnableLL": "Lightning Login",
    "Password": "Password",
    "BuiltInAuthenticator": "Built-In Authenticator",
    "WebAuthnRoamingAuthenticator": "Security Key",
    "CustomOtpDelivery": "Custom service",
    "PwlessPasskey": "Passwordless Login via Passkeys",
}
PHISHING_RESISTANT_VERIFICATION_METHODS = {
    "U2F",
    "BuiltInAuthenticator",
    "WebAuthnRoamingAuthenticator",
    "PwlessPasskey",
}
STANDARD_VERIFICATION_METHODS = {
    "Totp",
    "SalesforceAuthenticator",
    "LL",
    "EnableLL",
}
WEAK_OR_RECOVERY_VERIFICATION_METHODS = {
    "Sms",
    "Email",
    "TempCode",
    "Password",
    "CustomOtpDelivery",
}


class SfCommandError(RuntimeError):
    """Raised when an sf command fails."""


def progress(message: str) -> None:
    print(f"[mfa-audit] {message}", file=sys.stderr, flush=True)


def parse_cli_version(version_text: str | None) -> tuple[int, int, int] | None:
    """Extract a (major, minor, patch) tuple from `sf --version` output."""
    if not version_text:
        return None
    match = re.search(r"@salesforce/cli/(\d+)\.(\d+)\.(\d+)", version_text)
    if not match:
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def get_salesforce_cli_version() -> str | None:
    """Return the raw `sf --version` output, or None if it cannot be read."""
    try:
        completed = subprocess.run(
            ["sf", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or completed.stderr or "").strip()
    return output or None


def check_salesforce_cli() -> bool:
    """Confirm the Salesforce CLI (`sf`) is available and a known-good version.

    The Salesforce CLI is the primary external dependency: every org query and
    metadata retrieval shells out to `sf`. (Python is only an external
    dependency when the script is run as a plain .py file; a packaged
    executable bundles its own interpreter, but it still needs `sf` installed.)

    Missing CLI is a hard failure; an out-of-date CLI is a non-blocking warning.
    """
    if shutil.which("sf") is None:
        print("Cannot find primary dependency: Salesforce CLI", file=sys.stderr)
        return False

    version = parse_cli_version(get_salesforce_cli_version())
    if version is None:
        progress("Salesforce CLI confirmed (version could not be determined)")
        return True

    version_label = ".".join(str(part) for part in version)
    min_label = ".".join(str(part) for part in MIN_SF_CLI_VERSION)
    if version < MIN_SF_CLI_VERSION:
        progress(
            f"Salesforce CLI confirmed, but v{version_label} is below the known-good "
            f"minimum v{min_label}; run `sf update` to avoid command failures"
        )
    else:
        progress(f"Salesforce CLI confirmed (v{version_label})")
    return True


ORG_LIST_BUCKETS = ("nonScratchOrgs", "sandboxes", "devHubs", "scratchOrgs", "other")


def collect_orgs_from_list_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten and de-duplicate the bucketed `sf org list` payload.

    The CLI repeats the same org across buckets (e.g. an org can appear under
    both nonScratchOrgs and devHubs), so we key by username/orgId and OR the
    boolean role flags together.
    """
    result = (payload or {}).get("result", {}) or {}
    by_key: dict[str, dict[str, Any]] = {}
    for bucket in ORG_LIST_BUCKETS:
        for org in result.get(bucket, []) or []:
            key = org.get("username") or org.get("orgId") or org.get("alias")
            if not key:
                continue
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = dict(org)
                continue
            for flag in ("isSandbox", "isScratch", "isDevHub", "isDefaultUsername"):
                existing[flag] = bool(existing.get(flag)) or bool(org.get(flag))
            if not existing.get("alias") and org.get("alias"):
                existing["alias"] = org.get("alias")
            if not existing.get("connectedStatus") and org.get("connectedStatus"):
                existing["connectedStatus"] = org.get("connectedStatus")

    orgs = list(by_key.values())
    orgs.sort(
        key=lambda org: (
            not bool(org.get("isDefaultUsername")),
            (org.get("alias") or org.get("username") or "").lower(),
        )
    )
    return orgs


def describe_org_type(org: dict[str, Any]) -> str:
    if org.get("isScratch"):
        base = "scratch"
    elif org.get("isSandbox"):
        base = "sandbox"
    else:
        base = "production"
    if org.get("isDevHub"):
        base += " / dev hub"
    return base


def org_identifier(org: dict[str, Any]) -> str | None:
    return org.get("alias") or org.get("username")


def fetch_authenticated_orgs() -> list[dict[str, Any]]:
    progress("No --org provided; listing authenticated orgs via Salesforce CLI")
    payload = run_sf_json(["org", "list"])
    return collect_orgs_from_list_payload(payload)


def prompt_org_selection(orgs: list[dict[str, Any]]) -> str | None:
    if not orgs:
        print(
            "No authenticated Salesforce orgs were found. Run `sf org login web` or pass --org.",
            file=sys.stderr,
        )
        return None

    default_index = next(
        (index for index, org in enumerate(orgs) if org.get("isDefaultUsername")), None
    )

    print("\nNo --org provided. Select an org to audit:\n")
    for index, org in enumerate(orgs, start=1):
        alias = org.get("alias") or "(no alias)"
        marker = " [default]" if org.get("isDefaultUsername") else ""
        status = org.get("connectedStatus") or "Unknown"
        print(
            f"  {index}. {alias} — {org.get('username')} — "
            f"{describe_org_type(org)} — {status}{marker}"
        )

    suffix = f" [{default_index + 1}]" if default_index is not None else ""
    while True:
        choice = input(f"\nEnter a number{suffix} (or q to quit): ").strip()
        if choice.lower() in {"q", "quit", "exit"}:
            return None
        if not choice and default_index is not None:
            return org_identifier(orgs[default_index])
        if choice.isdigit():
            selected = int(choice)
            if 1 <= selected <= len(orgs):
                return org_identifier(orgs[selected - 1])
        print("Invalid selection. Please enter a listed number or q to quit.")


def resolve_target_org(args: argparse.Namespace) -> str | None:
    if args.org:
        return args.org
    if not sys.stdin.isatty():
        print(
            "No --org provided and no interactive terminal is available. "
            "Pass --org <alias|username>.",
            file=sys.stderr,
        )
        return None
    try:
        orgs = fetch_authenticated_orgs()
    except SfCommandError as exc:
        print(f"ERROR: could not list Salesforce orgs: {exc}", file=sys.stderr)
        return None
    return prompt_org_selection(orgs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit Salesforce MFA configuration for an org alias."
    )
    parser.add_argument(
        "--org",
        help=(
            "Salesforce CLI target org alias or username. If omitted, the script "
            "lists authenticated orgs from `sf org list` and prompts you to choose one."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full report as JSON.",
    )
    parser.add_argument(
        "--output",
        help="Optional file path to write the JSON report.",
    )
    parser.add_argument(
        "--markdown-file",
        help=(
            "Path for the Markdown report. Markdown is generated by default; "
            "use this to override the default file name, or --no-markdown to suppress it."
        ),
    )
    parser.add_argument(
        "--html-file",
        help="Optional file path to write an HTML report that renders directly in a browser.",
    )
    parser.add_argument(
        "--no-markdown",
        action="store_true",
        help="Suppress the default Markdown report generation.",
    )
    parser.add_argument(
        "--no-intro",
        action="store_true",
        help="Skip the animated MFA intro (useful for fast or sequential runs).",
    )
    parser.add_argument(
        "--large-org-sample",
        action="store_true",
        help="Use a sampled large-org mode: analyze the first bounded set of users instead of running fuller user counts.",
    )
    return parser.parse_args()


def run_sf_json(args: list[str], cwd: Path | None = None) -> Any:
    completed = subprocess.run(
        ["sf", *args, "--json"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SfCommandError(
            f"sf {' '.join(args)} failed\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return extract_json_payload(completed.stdout)


def run_sf_raw(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["sf", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SfCommandError(
            f"sf {' '.join(args)} failed\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return completed


def extract_json_payload(output: str) -> Any:
    output = output.strip()
    if not output:
        raise ValueError("No output returned from sf command.")

    for marker in ("{", "["):
        idx = output.find(marker)
        if idx != -1:
            candidate = output[idx:]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
    raise ValueError(f"Could not parse JSON payload from output:\n{output}")


def query_records(org_alias: str, soql: str) -> list[dict[str, Any]]:
    payload = run_sf_json(["data", "query", "--target-org", org_alias, "--query", soql])
    return payload["result"]["records"]


def query_total_size(org_alias: str, soql: str) -> int:
    payload = run_sf_json(["data", "query", "--target-org", org_alias, "--query", soql])
    return int(payload["result"].get("totalSize", 0))


def list_metadata(org_alias: str, metadata_type: str) -> dict[str, Any]:
    payload = run_sf_json(
        ["org", "list", "metadata", "--target-org", org_alias, "--metadata-type", metadata_type]
    )
    return payload


SFDX_PROJECT_TEMPLATE = {
    "packageDirectories": [{"path": "force-app", "default": True}],
    "namespace": "",
    "sfdcLoginUrl": "https://login.salesforce.com",
    "sourceApiVersion": "66.0",
}


def create_ephemeral_sfdx_project() -> Path:
    """Create a throwaway, self-contained SFDX project directory.

    ``sf project retrieve`` requires running inside a directory that contains a
    valid ``sfdx-project.json``. Relying on a file shipped next to the script
    breaks when packaged with PyInstaller (the binary unpacks to a temporary
    ``_MEI*`` directory with no project file), so we synthesize a minimal
    project on the fly instead.
    """
    # Resolve to the real path so it stays consistent with how `sf` resolves the
    # project root (on macOS the temp dir is a /var -> /private/var symlink).
    project_root = Path(tempfile.mkdtemp(prefix="mfa-audit-project-")).resolve()
    (project_root / "force-app").mkdir(parents=True, exist_ok=True)
    (project_root / "sfdx-project.json").write_text(
        json.dumps(SFDX_PROJECT_TEMPLATE, indent=2), encoding="utf-8"
    )
    return project_root


# Relative output directory (resolved against the project root / cwd). Using a
# relative path avoids `sf`'s "output dir outside project" check tripping over
# symlinked temp paths.
RETRIEVE_OUTPUT_SUBDIR = "retrieved"


def retrieve_security_settings(org_alias: str, repo_root: Path | None = None) -> dict[str, Any]:
    project_root = create_ephemeral_sfdx_project()
    output_dir = project_root / RETRIEVE_OUTPUT_SUBDIR
    try:
        progress("Retrieving Security settings metadata")
        run_sf_json(
            [
                "project",
                "retrieve",
                "start",
                "--target-org",
                org_alias,
                "--metadata",
                "Settings:Security",
                "--output-dir",
                RETRIEVE_OUTPUT_SUBDIR,
                "--ignore-conflicts",
            ],
            cwd=project_root,
        )

        security_path = output_dir / "settings" / "Security.settings-meta.xml"
        xml_text = security_path.read_text(encoding="utf-8")
        return parse_security_settings(xml_text)
    finally:
        shutil.rmtree(project_root, ignore_errors=True)


def parse_security_settings(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)

    def text_at(path: str) -> str | None:
        node = root.find(path, NAMESPACE)
        return node.text if node is not None else None

    def bool_at(path: str) -> bool | None:
        value = text_at(path)
        if value is None:
            return None
        return value.strip().lower() == "true"

    session = {
        "enableBuiltInAuthenticator": bool_at("md:sessionSettings/md:enableBuiltInAuthenticator"),
        "enableU2F": bool_at("md:sessionSettings/md:enableU2F"),
        "enableMFADirectUILoginOptIn": bool_at("md:sessionSettings/md:enableMFADirectUILoginOptIn"),
        "skipSFAWhenMFADirectUILogin": bool_at("md:sessionSettings/md:skipSFAWhenMFADirectUILogin"),
        "enableLightningLogin": bool_at("md:sessionSettings/md:enableLightningLogin"),
        "enableSMSIdentity": bool_at("md:sessionSettings/md:enableSMSIdentity"),
    }
    sso = {
        "enableSamlLogin": bool_at("md:singleSignOnSettings/md:enableSamlLogin"),
        "enableMultipleSamlConfigs": bool_at("md:singleSignOnSettings/md:enableMultipleSamlConfigs"),
        "isLoginWithSalesforceCredentialsDisabled": bool_at(
            "md:singleSignOnSettings/md:isLoginWithSalesforceCredentialsDisabled"
        ),
    }

    return {"sessionSettings": session, "singleSignOnSettings": sso}


def internal_user_where_clause(
    include_license_filter: bool = True, selective_user_type: bool = False
) -> str:
    excluded_user_types = [
        "Guest",
        "AutomatedProcess",
        "CspLitePortal",
        "PowerPartner",
        "SelfService",
        "CSPLiteUser",
    ]
    excluded_licenses = sorted(INTERNAL_LICENSE_EXCLUSIONS)
    user_type_filter = ", ".join(f"'{value}'" for value in excluded_user_types)
    license_filter = ", ".join(f"'{value}'" for value in excluded_licenses)
    where_lines = [
        "IsActive = true",
        "AND IsPortalEnabled = false",
    ]
    if selective_user_type:
        # Index-friendly positive predicate for large orgs; the broader
        # is_internal_user() check still filters edge cases in Python.
        where_lines.append("AND UserType = 'Standard'")
    else:
        where_lines.append(f"AND UserType NOT IN ({user_type_filter})")
    if include_license_filter:
        where_lines.append(f"AND Profile.UserLicense.Name NOT IN ({license_filter})")
    return "\n".join(where_lines)


def first_name_only(full_name: str | None) -> str:
    if not full_name:
        return ""
    parts = full_name.strip().split()
    return parts[0] if parts else ""


def display_user_identity(
    name: str | None, username: str | None, fallback: str | None = None
) -> str:
    first = first_name_only(name)
    if first and username:
        return f"{first} <{username}>"
    if username:
        return username
    if first:
        return first
    return fallback or "Unknown user"


def is_internal_user(user: dict[str, Any]) -> bool:
    user_type = (user.get("UserType") or "").strip()
    if not user_type:
        return False
    if user_type in NON_INTERACTIVE_USER_TYPES:
        return False
    if any(keyword in user_type.lower() for keyword in EXTERNAL_USER_TYPE_KEYWORDS):
        return False
    if user.get("IsPortalEnabled"):
        return False

    profile = user.get("Profile") or {}
    license_name = ((profile.get("UserLicense") or {}).get("Name") or "").strip()
    if license_name in INTERNAL_LICENSE_EXCLUSIONS:
        return False
    return True


def collect_privileged_reasons(
    user: dict[str, Any], assignment_rows: list[dict[str, Any]]
) -> list[str]:
    reasons: list[str] = []
    profile = user.get("Profile") or {}
    profile_name = profile.get("Name")
    if profile_name == "System Administrator":
        reasons.append("Profile: System Administrator")

    for field_name, label in PRIVILEGED_PERMISSION_FIELDS.items():
        if profile.get(field_name):
            reasons.append(f"Profile permission: {label}")

    for row in assignment_rows:
        permission_set = row.get("PermissionSet") or {}
        labels = [
            label
            for field_name, label in PRIVILEGED_PERMISSION_FIELDS.items()
            if permission_set.get(field_name)
        ]
        if labels:
            ps_label = permission_set.get("Label") or permission_set.get("Name") or "Unknown Permission Set"
            reasons.append(f"Permission set '{ps_label}': {', '.join(labels)}")

    # Preserve order but remove duplicates.
    seen: set[str] = set()
    unique_reasons: list[str] = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)
    return unique_reasons


def collect_mfa_assignments(user: dict[str, Any], assignment_rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    forced: list[str] = []
    bypassed: list[str] = []
    profile = user.get("Profile") or {}
    profile_name = profile.get("Name") or "Unknown Profile"

    if profile.get("PermissionsForceTwoFactor"):
        forced.append(f"Profile: {profile_name}")
    if profile.get("PermissionsBypassMFAForUiLogins"):
        bypassed.append(f"Profile: {profile_name}")

    for row in assignment_rows:
        permission_set = row.get("PermissionSet") or {}
        ps_label = permission_set.get("Label") or permission_set.get("Name") or "Unknown Permission Set"
        if permission_set.get("PermissionsForceTwoFactor"):
            forced.append(f"Permission set: {ps_label}")
        if permission_set.get("PermissionsBypassMFAForUiLogins"):
            bypassed.append(f"Permission set: {ps_label}")

    return {
        "force_mfa": dedupe(forced),
        "bypass_mfa": dedupe(bypassed),
    }


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def status_for_boolean(value: bool | None, pass_when_true: bool = True) -> str:
    if value is None:
        return "UNKNOWN"
    if value is pass_when_true:
        return "PASS"
    return "FAIL"


def status_icon(status: str) -> str:
    icons = {
        "PASS": "✅",
        "FAIL": "❌",
        "WARN": "⚠️",
        "INFO": "ℹ️",
        "UNKNOWN": "❔",
    }
    return icons.get(status, "•")


def status_color_class(status: str) -> str:
    return {
        "PASS": "status-green",
        "FAIL": "status-red",
        "WARN": "status-yellow",
        "UNKNOWN": "status-yellow",
        "INFO": "status-blue",
    }.get(status, "status-gray")


def build_section_score(statuses: list[str]) -> str:
    counts = {status: 0 for status in ("PASS", "FAIL", "WARN", "INFO", "UNKNOWN")}
    for status in statuses:
        counts[status] = counts.get(status, 0) + 1

    scored_total = counts["PASS"] + counts["FAIL"] + counts["WARN"] + counts["UNKNOWN"]
    if scored_total == 0:
        parts = ["informational section"]
    else:
        parts = [f"{counts['PASS']}/{scored_total} passing"]
        if counts["FAIL"]:
            parts.append(f"{status_icon('FAIL')} {counts['FAIL']} fail")
        if counts["WARN"]:
            parts.append(f"{status_icon('WARN')} {counts['WARN']} warning")
        if counts["UNKNOWN"]:
            parts.append(f"{status_icon('UNKNOWN')} {counts['UNKNOWN']} unknown")
        if counts["INFO"]:
            parts.append(f"{status_icon('INFO')} {counts['INFO']} info")

    return "> **Section score:** " + " | ".join(parts)


def add_section_header(lines: list[str], title: str, statuses: list[str]) -> None:
    lines.append("---")
    lines.append("")
    lines.append(f"## {title}")
    lines.append(build_section_score(statuses))
    lines.append("")


def overall_readiness(check_statuses: list[str]) -> tuple[str, str]:
    fail_count = sum(1 for status in check_statuses if status == "FAIL")
    warn_count = sum(1 for status in check_statuses if status == "WARN")
    unknown_count = sum(1 for status in check_statuses if status == "UNKNOWN")

    if fail_count:
        return ("FAIL", "Not ready")
    if warn_count or unknown_count:
        return ("WARN", "Needs review")
    return ("PASS", "Ready")


# Primary/secondary remediation guidance keyed by check id. Used to build the
# Resolutions section from the non-passing checks in the executive summary.
CHECK_RESOLUTIONS: dict[str, dict[str, str]] = {
    "direct_ui_mfa_enabled": {
        "primary": (
            "In Setup -> Identity -> Identity Verification (Session Settings), enable "
            "\"Require multi-factor authentication (MFA) for all direct UI logins to your "
            "Salesforce org\". This is the org-wide control Salesforce enforces in 2026, so "
            "turning it on is the cleanest fix."
        ),
        "secondary": (
            "If you cannot flip the org-wide setting yet, assign the \"Multi-Factor "
            "Authentication for User Interface Logins\" system permission via a permission "
            "set to all interactive users as a scoped, interim enforcement until the org-wide "
            "setting is enabled."
        ),
    },
    "built_in_authenticator_enabled": {
        "primary": (
            "In Setup -> Session Settings, under the MFA / identity verification methods, "
            "enable \"Let users verify their identity with a built-in authenticator\" so users "
            "can register a platform authenticator / passkey (Face ID, Touch ID, Windows "
            "Hello). This adds a phishing-resistant option with no hardware to distribute."
        ),
        "secondary": (
            "If built-in authenticators are not viable on your device fleet, enable physical "
            "security keys (U2F/WebAuthn) and authenticator apps so every user still has at "
            "least one strong, supported MFA method."
        ),
    },
    "security_key_enabled": {
        "primary": (
            "In Setup -> Session Settings, enable \"Let users use security keys (U2F or "
            "WebAuthn)\". This lets users register physical security keys and passkeys, the "
            "phishing-resistant method Salesforce recommends for privileged users."
        ),
        "secondary": (
            "If hardware keys are not broadly available, enable the built-in platform "
            "authenticator (passkeys) as the phishing-resistant alternative and prioritize "
            "distributing hardware keys to privileged users first."
        ),
    },
    "bypass_assignments": {
        "primary": (
            "Review the permission sets/profiles granting an MFA waiver (for example "
            "\"Waive Multi-Factor Authentication\" / MFA exemption permissions) and remove "
            "them from the flagged users so no standing bypass remains before enforcement."
        ),
        "secondary": (
            "Where a temporary exemption is genuinely required (for example a service or "
            "break-glass account), time-box it, document the business justification, and "
            "track it for removal ahead of the enforcement date."
        ),
    },
    "privileged_user_method_readiness": {
        "primary": (
            "Enable at least one phishing-resistant method (security keys/WebAuthn or the "
            "built-in authenticator) and ensure every privileged user (System Administrator, "
            "Modify All Data, View All Data, Customize Application, Author Apex) is registered "
            "for it before the July 1, 2026 privileged-user deadline."
        ),
        "secondary": (
            "Apply least privilege: reduce or reassign the elevated permissions so fewer "
            "users fall under the phishing-resistant requirement, then enroll the remaining "
            "privileged set."
        ),
    },
    "sso_signal_validation": {
        "primary": (
            "Configure your identity provider to enforce phishing-resistant MFA and return "
            "the corresponding AMR/ACR values (for example phr/phrh or FIDO2/WebAuthn), then "
            "confirm LoginHistory AMR signals reflect strong methods across every SSO login "
            "path."
        ),
        "secondary": (
            "For any SSO path that cannot return phishing-resistant signals, enable "
            "Salesforce-side MFA as a backstop and monitor LoginHistory for weak or missing "
            "AMR signals."
        ),
    },
}

DEFAULT_RESOLUTION = {
    "primary": (
        "Review the related Salesforce MFA setting or permission assignment behind this "
        "check and bring it into line with the 2026 MFA enforcement requirements."
    ),
    "secondary": (
        "If the primary fix cannot be applied immediately, document a time-boxed interim "
        "control and schedule the change before the enforcement deadline."
    ),
}


def build_resolution_entries(checks: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Build primary/secondary resolutions for non-passing executive-summary checks."""
    entries: list[dict[str, str]] = []
    for check in checks:
        status = check.get("status", "INFO")
        if status not in ("FAIL", "WARN", "UNKNOWN"):
            continue
        resolution = CHECK_RESOLUTIONS.get(check.get("id", ""), DEFAULT_RESOLUTION)
        entries.append(
            {
                "issue": check.get("message", check.get("id", "Check")),
                "status": status,
                "primary": resolution["primary"],
                "secondary": resolution["secondary"],
            }
        )
    return entries


def split_signal_codes(raw_value: Any) -> list[str]:
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        return dedupe([str(item).strip() for item in raw_value if str(item).strip()])

    text = str(raw_value).strip()
    if not text:
        return []

    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return dedupe([str(item).strip() for item in parsed if str(item).strip()])

    return dedupe([part.strip() for part in re.split(r"[\s,;|]+", text) if part.strip()])


def classify_signal_code(code: str) -> tuple[str, str]:
    normalized = code.strip().lower()
    if normalized in PHISHING_RESISTANT_AMR_CODES:
        return ("PASS", "Phishing-resistant MFA")
    if normalized in STANDARD_MFA_AMR_CODES:
        return ("WARN", "Standard MFA")
    if normalized in WEAK_OR_NO_MFA_AMR_CODES:
        return ("FAIL", "Weak / no MFA")
    return ("UNKNOWN", "Unrecognized")


def classify_signal_codes(codes: list[str]) -> dict[str, Any]:
    phishing_resistant: list[str] = []
    standard: list[str] = []
    weak: list[str] = []
    unknown: list[str] = []

    for code in codes:
        status, label = classify_signal_code(code)
        if label == "Phishing-resistant MFA":
            phishing_resistant.append(code)
        elif label == "Standard MFA":
            standard.append(code)
        elif label == "Weak / no MFA":
            weak.append(code)
        else:
            unknown.append(code)

    if phishing_resistant:
        return {
            "status": "PASS",
            "label": "Phishing-resistant MFA",
            "matchedCodes": dedupe(phishing_resistant),
            "unknownCodes": dedupe(unknown),
        }
    if standard:
        return {
            "status": "WARN",
            "label": "Standard MFA",
            "matchedCodes": dedupe(standard),
            "unknownCodes": dedupe(unknown + weak),
        }
    if weak:
        return {
            "status": "FAIL",
            "label": "Weak / no MFA",
            "matchedCodes": dedupe(weak),
            "unknownCodes": dedupe(unknown),
        }
    if unknown:
        return {
            "status": "UNKNOWN",
            "label": "Unrecognized",
            "matchedCodes": [],
            "unknownCodes": dedupe(unknown),
        }
    return {
        "status": "UNKNOWN",
        "label": "No AMR signal",
        "matchedCodes": [],
        "unknownCodes": [],
    }


def classify_verification_method(method: str | None) -> tuple[str, str]:
    if not method:
        return ("UNKNOWN", "Unknown")
    if method in PHISHING_RESISTANT_VERIFICATION_METHODS:
        return ("PASS", "Phishing-resistant MFA")
    if method in STANDARD_VERIFICATION_METHODS:
        return ("WARN", "Standard MFA")
    if method in WEAK_OR_RECOVERY_VERIFICATION_METHODS:
        return ("FAIL", "Weak / recovery / not phishing-resistant")
    return ("UNKNOWN", "Unrecognized")


def summarize_non_sso_verification_statuses(analysis: dict[str, Any]) -> list[str]:
    if analysis["sampleSize"] == 0:
        return ["INFO"]
    if analysis["phishingResistantCount"]:
        return ["PASS"]
    if analysis["standardCount"]:
        return ["WARN"]
    if analysis["weakOrRecoveryCount"]:
        return ["FAIL"]
    if analysis["unrecognizedCount"]:
        return ["UNKNOWN"]
    return ["INFO"]


def describe_sobject_field_names(org_alias: str, sobject_name: str) -> set[str]:
    payload = run_sf_json(
        ["force", "schema", "sobject", "describe", "--sobject", sobject_name, "--target-org", org_alias]
    )
    return {
        field["name"]
        for field in payload["result"].get("fields", [])
        if isinstance(field, dict) and field.get("name")
    }


def lookup_user_identities(org_alias: str, user_ids: list[str]) -> dict[str, dict[str, str | None]]:
    user_map: dict[str, dict[str, str | None]] = {}
    if not user_ids:
        return user_map

    for index in range(0, len(user_ids), 100):
        chunk = user_ids[index : index + 100]
        quoted_ids = ", ".join(f"'{escape_soql_literal(user_id)}'" for user_id in chunk)
        rows = query_records(org_alias, f"SELECT Id, Name, Username FROM User WHERE Id IN ({quoted_ids})")
        for row in rows:
            user_map[row["Id"]] = {
                "name": row.get("Name"),
                "username": row.get("Username"),
            }
    return user_map


def fetch_user_rows_by_ids(org_alias: str, user_ids: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not user_ids:
        return rows

    for index in range(0, len(user_ids), 100):
        chunk = user_ids[index : index + 100]
        quoted_ids = ", ".join(f"'{escape_soql_literal(user_id)}'" for user_id in chunk)
        rows.extend(
            query_records(
                org_alias,
                f"SELECT {USER_SELECT_FIELDS} FROM User WHERE Id IN ({quoted_ids})",
            )
        )
    return rows


def summarize_sso_signal_statuses(analysis: dict[str, Any], sso_enabled: bool) -> list[str]:
    if not sso_enabled:
        return ["INFO"]
    if not analysis["fieldAvailability"]["authMethodReference"]:
        return ["UNKNOWN"]
    if analysis["sampleSize"] == 0:
        return ["UNKNOWN"]
    if analysis["phishingResistantMatchCount"]:
        return ["PASS"]
    if analysis["standardMatchCount"]:
        return ["WARN"]
    if analysis["weakOrNoMfaMatchCount"]:
        return ["FAIL"]
    if analysis["rowsWithAuthMethodReference"] == 0:
        return ["WARN"]
    if analysis["unrecognizedSignalCount"]:
        return ["UNKNOWN"]
    return ["INFO"]


def count_failed_security_checks(report: dict[str, Any]) -> int:
    security_check_ids = {
        "direct_ui_mfa_enabled",
        "built_in_authenticator_enabled",
        "security_key_enabled",
        "privileged_user_method_readiness",
    }
    return sum(
        1
        for check in report["checks"]
        if check.get("id") in security_check_ids and check.get("status") == "FAIL"
    )


def build_issue_scatterplot_points(report: dict[str, Any]) -> list[dict[str, Any]]:
    session_settings = report["settings"]["sessionSettings"]
    summary = report["summary"]

    lack_of_mfa_options = int(not bool(session_settings["enableBuiltInAuthenticator"])) + int(
        not bool(session_settings["enableU2F"])
    )
    failed_security_checks = count_failed_security_checks(report)

    sso_signal_analysis = report.get("ssoLoginSignalAnalysis") or {}
    logins_without_acceptable_signal = (
        int(sso_signal_analysis.get("missingSignalCount") or 0)
        + int(sso_signal_analysis.get("weakOrNoMfaMatchCount") or 0)
        + int(sso_signal_analysis.get("unrecognizedSignalCount") or 0)
    )
    signal_sample_size = int(sso_signal_analysis.get("sampleSize") or 0)

    return [
        {
            "label": "Lack of MFA options",
            "count": lack_of_mfa_options,
            "description": "Disabled built-in authenticator and hardware key options.",
        },
        {
            "label": "Failed security checks",
            "count": failed_security_checks,
            "description": "Security-focused audit checks currently failing for this org.",
        },
        {
            "label": "Logins without acceptable MFA signal",
            "count": logins_without_acceptable_signal,
            "description": (
                "Recent logins classified weak/none/unrecognized/missing "
                f"(not standard or phishing-resistant) out of {signal_sample_size} sampled logins."
            ),
        },
        {
            "label": "Elevated permissions",
            "count": summary["privilegedInternalUserCount"],
            "description": "Privileged internal users in phishing-resistant MFA scope.",
        },
        {
            "label": "Waive MFA permission instances",
            "count": summary["usersWithBypassAssignments"],
            "description": "Users with MFA bypass / waiver assignments.",
        },
        {
            "label": "Users uncovered if UI MFA off",
            "count": int(summary.get("uncoveredInternalUsersIfOrgSwitchOff") or 0),
            "description": "Internal users without permission-based MFA coverage if org-wide UI MFA is disabled.",
        },
    ]


def fetch_recent_login_history_signal_analysis(org_alias: str) -> dict[str, Any]:
    progress("Analyzing recent LoginHistory rows for AMR/ACR SSO signals")
    field_names = describe_sobject_field_names(org_alias, "LoginHistory")
    acr_field = next((field for field in ACR_LOGIN_HISTORY_FIELD_CANDIDATES if field in field_names), None)
    query_fields = [
        "Id",
        "LoginTime",
        "Status",
        "UserId",
        "LoginType",
        "Application",
        "AuthenticationServiceId",
    ]
    if "AuthMethodReference" in field_names:
        query_fields.append("AuthMethodReference")
    if acr_field:
        query_fields.append(acr_field)

    login_rows = query_records(
        org_alias,
        f"SELECT {', '.join(query_fields)} FROM LoginHistory ORDER BY LoginTime DESC LIMIT 100",
    )
    user_map = lookup_user_identities(
        org_alias,
        sorted({row.get("UserId") for row in login_rows if row.get("UserId")}),
    )

    observed_code_counts: Counter[str] = Counter()
    signal_rows: list[dict[str, Any]] = []
    classification_counts: Counter[str] = Counter()
    rows_with_auth_method_reference = 0
    rows_with_acr = 0
    sso_login_count = 0

    for row in login_rows:
        user_identity = user_map.get(row.get("UserId"), {})
        auth_method_reference = row.get("AuthMethodReference") if "AuthMethodReference" in field_names else None
        acr_value = row.get(acr_field) if acr_field else None
        codes = split_signal_codes(auth_method_reference)
        classification = classify_signal_codes(codes)
        is_sso = bool(row.get("AuthenticationServiceId"))

        if auth_method_reference:
            rows_with_auth_method_reference += 1
        if acr_value:
            rows_with_acr += 1
        if is_sso:
            sso_login_count += 1
        classification_counts[classification["label"]] += 1

        for code in codes:
            observed_code_counts[code.strip().lower()] += 1

        if is_sso or auth_method_reference or acr_value:
            signal_rows.append(
                {
                    "loginTime": row.get("LoginTime"),
                    "status": row.get("Status"),
                    "userId": row.get("UserId"),
                    "userName": user_identity.get("name"),
                    "username": user_identity.get("username"),
                    "loginType": row.get("LoginType"),
                    "application": row.get("Application"),
                    "authenticationServiceId": row.get("AuthenticationServiceId"),
                    "authMethodReference": auth_method_reference,
                    "acrContextClassReference": acr_value,
                    "classification": classification["label"],
                    "classificationStatus": classification["status"],
                    "matchedCodes": classification["matchedCodes"],
                    "unknownCodes": classification["unknownCodes"],
                    "isSso": is_sso,
                }
            )

    observed_codes = []
    for code, count in observed_code_counts.most_common():
        code_status, code_label = classify_signal_code(code)
        observed_codes.append(
            {
                "code": code,
                "count": count,
                "classification": code_label,
                "status": code_status,
            }
        )

    return {
        "sampleSize": len(login_rows),
        "ssoLoginCount": sso_login_count,
        "rowsWithAuthMethodReference": rows_with_auth_method_reference,
        "rowsWithAcrContextReference": rows_with_acr,
        "phishingResistantMatchCount": classification_counts["Phishing-resistant MFA"],
        "standardMatchCount": classification_counts["Standard MFA"],
        "weakOrNoMfaMatchCount": classification_counts["Weak / no MFA"],
        "unrecognizedSignalCount": classification_counts["Unrecognized"],
        "missingSignalCount": classification_counts["No AMR signal"],
        "fieldAvailability": {
            "authMethodReference": "AuthMethodReference" in field_names,
            "acrContextClassReference": acr_field is not None,
            "acrFieldName": acr_field,
        },
        "observedCodes": observed_codes,
        "signalRows": signal_rows[:20],
    }


def fetch_recent_non_sso_verification_analysis(org_alias: str) -> dict[str, Any]:
    progress("Analyzing verification history for non-SSO MFA methods")
    verification_rows = query_records(
        org_alias,
        (
            "SELECT Id, LoginHistoryId, UserId, VerificationMethod, VerificationTime, Status "
            "FROM VerificationHistory ORDER BY VerificationTime DESC LIMIT 100"
        ),
    )

    login_history_ids = sorted(
        {row.get("LoginHistoryId") for row in verification_rows if row.get("LoginHistoryId")}
    )
    login_rows_by_id: dict[str, dict[str, Any]] = {}
    for index in range(0, len(login_history_ids), 100):
        chunk = login_history_ids[index : index + 100]
        quoted_ids = ", ".join(f"'{escape_soql_literal(login_id)}'" for login_id in chunk)
        login_rows = query_records(
            org_alias,
            (
                "SELECT Id, LoginTime, LoginType, Application, AuthenticationServiceId "
                f"FROM LoginHistory WHERE Id IN ({quoted_ids})"
            ),
        )
        for row in login_rows:
            login_rows_by_id[row["Id"]] = row

    non_sso_rows = []
    user_map = lookup_user_identities(
        org_alias,
        sorted({row.get("UserId") for row in verification_rows if row.get("UserId")}),
    )
    method_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    for row in verification_rows:
        login_row = login_rows_by_id.get(row.get("LoginHistoryId"))
        if login_row and login_row.get("AuthenticationServiceId"):
            continue

        method = row.get("VerificationMethod")
        status, category = classify_verification_method(method)
        label = VERIFICATION_METHOD_LABELS.get(method or "", method or "Unknown")
        method_counts[method or "Unknown"] += 1
        category_counts[category] += 1
        identity = user_map.get(row.get("UserId"), {})

        non_sso_rows.append(
            {
                "verificationTime": row.get("VerificationTime"),
                "status": row.get("Status"),
                "verificationMethod": method,
                "verificationMethodLabel": label,
                "classification": category,
                "classificationStatus": status,
                "loginHistoryId": row.get("LoginHistoryId"),
                "loginTime": (login_row or {}).get("LoginTime"),
                "loginType": (login_row or {}).get("LoginType"),
                "application": (login_row or {}).get("Application"),
                "userId": row.get("UserId"),
                "userName": identity.get("name"),
                "username": identity.get("username"),
            }
        )

    observed_methods = []
    for method, count in method_counts.most_common():
        status, category = classify_verification_method(None if method == "Unknown" else method)
        observed_methods.append(
            {
                "method": method,
                "label": VERIFICATION_METHOD_LABELS.get(method, method),
                "count": count,
                "classification": category,
                "status": status,
            }
        )

    return {
        "sampleSize": len(verification_rows),
        "nonSsoVerificationCount": len(non_sso_rows),
        "phishingResistantCount": category_counts["Phishing-resistant MFA"],
        "standardCount": category_counts["Standard MFA"],
        "weakOrRecoveryCount": category_counts["Weak / recovery / not phishing-resistant"],
        "unrecognizedCount": category_counts["Unrecognized"],
        "observedMethods": observed_methods,
        "verificationRows": non_sso_rows[:20],
    }


def render_issue_scatterplot_svg(points: list[dict[str, Any]]) -> str:
    width = 840
    height = 440
    margin_left = 90
    margin_right = 90
    margin_top = 60
    margin_bottom = 110
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    max_count = max((point["count"] for point in points), default=1)
    max_count = max(max_count, 1)
    tick_candidates = [1, 2, 5, 10, 20, 50, 100]
    tick_values = sorted({tick for tick in tick_candidates if tick <= max_count} | {1, max_count})

    # Headroom buffer so the largest bubble's center sits below the top edge
    # (and avoids a divide-by-zero when max_count == 1).
    log_buffer = 0.25
    axis_log_max = (math.log10(max_count) if max_count > 1 else 0.0) + log_buffer

    def x_for(index: int) -> float:
        if len(points) == 1:
            return margin_left + plot_width / 2
        return margin_left + (index / (len(points) - 1)) * plot_width

    def y_for(count: int) -> float:
        if count <= 0:
            return margin_top + plot_height
        return margin_top + plot_height - (math.log10(count) / axis_log_max) * plot_height

    # Cap bubble size to the available headroom/margins so even the largest
    # count renders as a fully visible circle (the highest point is the tightest
    # vertical constraint); smaller bubbles keep their square-root differentiation.
    max_radius = max(
        16.0,
        min(y_for(max_count), margin_left, margin_right, margin_bottom) - 4,
    )

    def radius_for(count: int) -> float:
        return min(12 + math.sqrt(count) * 5, max_radius)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" '
        'aria-label="Log-scaled scatterplot of MFA issues by category">',
        '<rect x="0" y="0" width="100%" height="100%" fill="white" />',
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + plot_height}" '
        'stroke="#4b5563" stroke-width="1.5" />',
        f'<line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{margin_left + plot_width}" '
        f'y2="{margin_top + plot_height}" stroke="#4b5563" stroke-width="1.5" />',
    ]

    for tick in tick_values:
        y = y_for(tick)
        lines.append(
            f'<line x1="{margin_left}" y1="{y}" x2="{margin_left + plot_width}" y2="{y}" '
            'stroke="#e5e7eb" stroke-width="1" />'
        )
        lines.append(
            f'<text x="{margin_left - 12}" y="{y + 4}" text-anchor="end" font-size="12" '
            f'fill="#6b7280">{tick}</text>'
        )

    for index, point in enumerate(points):
        x = x_for(index)
        y = y_for(point["count"])
        radius = radius_for(point["count"])
        lines.append(
            f'<circle cx="{x}" cy="{y}" r="{radius}" fill="#bfdbfe" stroke="#2563eb" '
            'stroke-width="2" fill-opacity="0.9" />'
        )
        lines.append(
            f'<text x="{x}" y="{y + 4}" text-anchor="middle" font-size="13" font-weight="600" '
            f'fill="#111827">{point["count"]}</text>'
        )
        label_lines = textwrap.wrap(point["label"], width=16) or [point["label"]]
        label_tspans = "".join(
            f'<tspan x="{x}" dy="{0 if line_index == 0 else 14}">{html.escape(line)}</tspan>'
            for line_index, line in enumerate(label_lines)
        )
        lines.append(
            f'<text x="{x}" y="{margin_top + plot_height + 24}" text-anchor="middle" font-size="12" '
            f'fill="#374151">{label_tspans}</text>'
        )

    lines.extend(
        [
            f'<text x="26" y="{margin_top + plot_height / 2}" text-anchor="middle" font-size="13" '
            f'fill="#374151" transform="rotate(-90 26 {margin_top + plot_height / 2})">Occurrences (count, log scale)</text>',
            f'<text x="{margin_left + plot_width / 2}" y="{height - 18}" text-anchor="middle" font-size="13" '
            'fill="#374151">MFA issue category</text>',
            "</svg>",
        ]
    )
    return "\n".join(lines)


def convert_svg_to_png(svg_path: Path, png_path: Path) -> bool:
    with tempfile.TemporaryDirectory(prefix="mfa-scatterplot-") as temp_dir:
        completed = subprocess.run(
            [
                "qlmanage",
                "-t",
                "-s",
                "1600",
                "-o",
                temp_dir,
                str(svg_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            return False

        generated_png = Path(temp_dir) / f"{svg_path.name}.png"
        if not generated_png.exists():
            return False

        png_path.write_bytes(generated_png.read_bytes())
        return True


def write_scatterplot_assets(report: dict[str, Any], markdown_path: Path) -> tuple[Path, Path | None]:
    scatterplot_points = build_issue_scatterplot_points(report)
    scatterplot_filename = f"{markdown_path.stem}-scatterplot.svg"
    scatterplot_path = markdown_path.with_name(scatterplot_filename)
    scatterplot_path.write_text(
        render_issue_scatterplot_svg(scatterplot_points),
        encoding="utf-8",
    )
    png_path = markdown_path.with_name(f"{markdown_path.stem}-scatterplot.png")
    if convert_svg_to_png(scatterplot_path, png_path):
        return scatterplot_path, png_path
    return scatterplot_path, None


def render_html_report(report: dict[str, Any], scatterplot_svg: str | None = None) -> str:
    org = report["org"]
    run = report["run"]
    summary = report["summary"]
    settings = report["settings"]
    sampling = report.get("sampling", {"enabled": False})
    session_settings = settings["sessionSettings"]
    sso_settings = settings["singleSignOnSettings"]
    mfa_methods_access = report["details"]["mfaMethodsAccess"]
    sso_signal_analysis = report["details"].get(
        "ssoLoginSignalAnalysis",
        {
            "sampleSize": 0,
            "ssoLoginCount": 0,
            "rowsWithAuthMethodReference": 0,
            "rowsWithAcrContextReference": 0,
            "phishingResistantMatchCount": 0,
            "standardMatchCount": 0,
            "weakOrNoMfaMatchCount": 0,
            "unrecognizedSignalCount": 0,
            "missingSignalCount": 0,
            "fieldAvailability": {
                "authMethodReference": False,
                "acrContextClassReference": False,
                "acrFieldName": None,
            },
            "observedCodes": [],
            "signalRows": [],
        },
    )
    non_sso_verification_analysis = report["details"].get(
        "nonSsoVerificationAnalysis",
        {
            "sampleSize": 0,
            "nonSsoVerificationCount": 0,
            "phishingResistantCount": 0,
            "standardCount": 0,
            "weakOrRecoveryCount": 0,
            "unrecognizedCount": 0,
            "observedMethods": [],
            "verificationRows": [],
        },
    )
    issue_points = build_issue_scatterplot_points(report)
    checks = report["checks"]
    render_limit = USER_RENDER_LIMIT if sampling.get("enabled") else None
    privileged = report["details"]["privilegedUsers"][:render_limit]
    bypass_users = report["details"]["usersWithBypassAssignments"][:render_limit]
    uncovered = report["details"]["uncoveredInternalUsersIfOrgSwitchOff"][:render_limit]
    manual_review_items = [item for item in report["manualReview"] if item["requiredWhen"]]
    check_statuses = [check["status"] for check in checks]
    overall_status, overall_label = overall_readiness(check_statuses)

    def check_detail(check: dict[str, Any]) -> str:
        if "value" in check:
            return f"Value: {check['value']}"
        if "count" in check:
            return f"Count: {check['count']}"
        if "samlConfigCount" in check:
            return f"SAML config(s): {check['samlConfigCount']}"
        return ""

    exec_card_blocks = [
        '<div class="exec-card hero {cls}">'
        '<div class="card-label">Overall readiness</div>'
        '<div class="card-value">{icon} {label}</div>'
        '<div class="card-subvalue">{score}</div>'
        "</div>".format(
            cls=status_color_class(overall_status),
            icon=html.escape(status_icon(overall_status)),
            label=html.escape(overall_label),
            score=html.escape(
                build_section_score(check_statuses).replace("> **Section score:** ", "")
            ),
        )
    ]
    for check in checks:
        check_status = check.get("status", "INFO")
        detail = check_detail(check)
        exec_card_blocks.append(
            '<div class="exec-card {cls}">'
            '<div class="card-label">{label}</div>'
            '<div class="card-value">{icon} {status}</div>'
            "{subvalue}"
            "</div>".format(
                cls=status_color_class(check_status),
                label=html.escape(check.get("message", check.get("id", "Check"))),
                icon=html.escape(status_icon(check_status)),
                status=html.escape(check_status),
                subvalue=(
                    f'<div class="card-subvalue">{html.escape(detail)}</div>' if detail else ""
                ),
            )
        )
    exec_cards_html = "\n    ".join(exec_card_blocks)

    resolution_entries = build_resolution_entries(checks)
    if resolution_entries:
        resolution_cards = "\n    ".join(
            '<div class="exec-card {cls}">'
            '<div class="card-label">{icon} {issue}</div>'
            '<div class="card-subvalue"><strong>Primary:</strong> {primary}</div>'
            '<div class="card-subvalue"><strong>Secondary:</strong> {secondary}</div>'
            "</div>".format(
                cls=status_color_class(entry["status"]),
                icon=html.escape(status_icon(entry["status"])),
                issue=html.escape(entry["issue"]),
                primary=html.escape(entry["primary"]),
                secondary=html.escape(entry["secondary"]),
            )
            for entry in resolution_entries
        )
        resolutions_html = (
            "\n  <h2>Resolutions</h2>"
            '\n  <p class="muted">Suggested primary and secondary fixes for the issues flagged in the executive summary.</p>'
            '\n  <div class="exec-cards">\n    '
            + resolution_cards
            + "\n  </div>"
        )
    else:
        resolutions_html = (
            "\n  <h2>Resolutions</h2>"
            '\n  <p class="muted">No outstanding issues from the executive summary checks &mdash; no resolutions required.</p>'
        )

    def status_badge(status: str) -> str:
        return f'<span class="status">{html.escape(status_icon(status))} {html.escape(status)}</span>'

    def item_list(items: list[str]) -> str:
        if not items:
            return "<ul><li>None</li></ul>"
        return "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in items) + "</ul>"

    def render_signal_rows() -> str:
        rows = sso_signal_analysis["signalRows"]
        if not rows:
            return '<div class="muted">No recent LoginHistory rows in the 100-login sample exposed an AMR signal or an SSO-authentication service reference.</div>'
        return "".join(
            "<li>"
            + f"{status_badge(row['classificationStatus'])} "
            + html.escape(row["loginTime"] or "Unknown time")
            + " | "
            + html.escape(display_user_identity(row.get("userName"), row.get("username"), row.get("userId")))
            + " | "
            + html.escape(row.get("application") or "Unknown application")
            + " | AMR: "
            + f"<code>{html.escape(row.get('authMethodReference') or 'none')}</code>"
            + " | ACR: "
            + f"<code>{html.escape(row.get('acrContextClassReference') or 'not available')}</code>"
            + " | Match: "
            + html.escape(row["classification"])
            + "</li>"
            for row in rows
        )

    def render_verification_rows() -> str:
        rows = non_sso_verification_analysis["verificationRows"]
        if not rows:
            return '<div class="muted">No recent non-SSO verification history rows were available in the sampled VerificationHistory data.</div>'
        return "".join(
            "<li>"
            + f"{status_badge(row['classificationStatus'])} "
            + html.escape(row["verificationTime"] or "Unknown time")
            + " | "
            + html.escape(display_user_identity(row.get("userName"), row.get("username"), row.get("userId")))
            + " | "
            + html.escape(row.get("application") or "Unknown application")
            + " | Method: "
            + f"<code>{html.escape(row.get('verificationMethod') or 'unknown')}</code>"
            + " | Label: "
            + html.escape(row.get("verificationMethodLabel") or "Unknown")
            + " | Match: "
            + html.escape(row["classification"])
            + "</li>"
            for row in rows
        )

    scatterplot_block = (
        scatterplot_svg
        if scatterplot_svg
        else "<p class=\"muted\">Scatterplot image unavailable for this HTML export.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Salesforce MFA Audit Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #111827; background: #ffffff; line-height: 1.5; }}
    h1, h2, h3 {{ margin: 0 0 12px 0; }}
    h2 {{ margin-top: 28px; padding-top: 20px; border-top: 1px solid #e5e7eb; }}
    .muted {{ color: #6b7280; }}
    .score {{ color: #374151; font-weight: 600; margin-bottom: 12px; }}
    .status {{ display: inline-block; padding: 2px 8px; border: 1px solid #d1d5db; border-radius: 999px; font-size: 12px; }}
    .lead {{ margin-bottom: 18px; }}
    .card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin: 14px 0; }}
    .exec-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin: 8px 0 20px; }}
    .exec-card {{ border-radius: 14px; padding: 16px; border: 1px solid transparent; }}
    .exec-card .card-label {{ font-size: 0.92rem; font-weight: 600; color: #475569; margin-bottom: 6px; }}
    .exec-card .card-value {{ font-size: 1.35rem; font-weight: 700; color: #0f172a; }}
    .exec-card .card-subvalue {{ font-size: 0.9rem; color: #334155; margin-top: 6px; }}
    .exec-card.hero {{ grid-column: 1 / -1; }}
    .exec-card.hero .card-value {{ font-size: 1.7rem; }}
    .status-green {{ background: #ecfdf5; border-color: #86efac; }}
    .status-yellow {{ background: #fffbeb; border-color: #fcd34d; }}
    .status-red {{ background: #fef2f2; border-color: #fca5a5; }}
    .status-blue {{ background: #eff6ff; border-color: #93c5fd; }}
    .status-gray {{ background: #f8fafc; border-color: #cbd5e1; }}
    details.collapsible > summary {{ cursor: pointer; font-weight: 600; font-size: 1.05em; display: flex; align-items: center; justify-content: space-between; gap: 12px; list-style-position: inside; }}
    details.collapsible > summary:hover {{ color: #2563eb; }}
    details.collapsible[open] > summary {{ margin-bottom: 12px; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px; }}
    details.collapsible .summary-count {{ font-weight: 500; color: #6b7280; font-size: 0.85em; white-space: nowrap; }}
    details.collapsible .summary-hint {{ font-weight: 400; color: #6b7280; font-size: 0.82em; font-style: italic; }}
    details.collapsible[open] > summary .summary-hint {{ display: none; }}
    details.collapsible .collapsible-body > div {{ margin: 6px 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
    ul {{ margin: 8px 0 0 20px; }}
    li {{ margin: 4px 0; }}
    .svg-wrap {{ background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; overflow-x: auto; }}
    .check-list li {{ margin-bottom: 8px; }}
  </style>
</head>
<body>
  <h1>Salesforce MFA Audit Report</h1>
  <div class="muted">Run at: {html.escape(run["generatedAt"])}</div>

  <h2>Executive Summary</h2>
  <div class="exec-cards">
    {exec_cards_html}
  </div>
  <ul>
    <li><strong>Primary takeaway:</strong> {summary["privilegedInternalUserCount"]} privileged internal user(s) must be ready for phishing-resistant MFA, and {summary["usersWithBypassAssignments"]} bypass assignment(s) were detected.</li>
    <li><strong>Coverage snapshot:</strong> {summary["activeInternalUserCount"]} active internal user(s), {summary["usersWithPermissionBasedUiMfa"]} user(s) with permission-based UI MFA, {summary["uncoveredInternalUsersIfOrgSwitchOff"]} user(s) not covered if org-wide UI MFA is off.</li>
    <li><strong>Per-user MFA methods:</strong> {html.escape('visible for ' + str(summary['usersWithVisibleMfaMethods']) + ' internal user(s).' if mfa_methods_access['available'] else 'unavailable. ' + mfa_methods_access['reason'])}</li>
    <li><strong>SSO snapshot:</strong> {summary["samlConfigCount"]} SAML config(s) detected.</li>
    {'<li><strong>Sampling note:</strong> User-based counts and user lists in this report are based on the first ' + str(sampling.get("userQueryLimit")) + ' queried users; displayed user sections are capped to ' + str(sampling.get("userRenderLimit")) + ' rows.</li>' if sampling.get("enabled") else ''}
  </ul>

  <h2>Org</h2>
  <ul>
    <li><strong>Alias:</strong> {html.escape(org["alias"])}</li>
    <li><strong>Username:</strong> {html.escape(org["username"])}</li>
    <li><strong>Instance:</strong> {html.escape(org["instanceUrl"])}</li>
  </ul>

  <h2>Issue Scatterplot</h2>
  <div class="lead">Point positions use a log-scaled Y-axis so a very large category does not visually flatten the smaller issue categories. Raw counts are still shown inside each point and in the summary below.</div>
  <div class="svg-wrap">{scatterplot_block}</div>
  <ul>
    {''.join(f'<li><strong>{html.escape(point["label"])}:</strong> {point["count"]} occurrence(s) - {html.escape(point["description"])}</li>' for point in issue_points)}
  </ul>

  <h2>Configurations</h2>
  <div class="grid">
    <div class="card">
      <h3>Security settings</h3>
      <ul>
        <li>{status_badge(status_for_boolean(session_settings["enableMFADirectUILoginOptIn"]))} Direct UI MFA required: <code>{session_settings["enableMFADirectUILoginOptIn"]}</code></li>
        <li>{status_badge(status_for_boolean(session_settings["enableBuiltInAuthenticator"]))} Built-in authenticator enabled: <code>{session_settings["enableBuiltInAuthenticator"]}</code></li>
        <li>{status_badge(status_for_boolean(session_settings["enableU2F"]))} Security key / U2F enabled: <code>{session_settings["enableU2F"]}</code></li>
        <li>{status_badge("INFO")} Lightning Login enabled: <code>{session_settings["enableLightningLogin"]}</code></li>
        <li>{status_badge("INFO")} SMS identity enabled: <code>{session_settings["enableSMSIdentity"]}</code></li>
      </ul>
    </div>
    <div class="card">
      <h3>Single sign-on settings</h3>
      <ul>
        <li>{status_badge("WARN" if sso_settings["enableSamlLogin"] else "INFO")} SAML login enabled: <code>{sso_settings["enableSamlLogin"]}</code></li>
        <li>{status_badge("INFO")} Multiple SAML configs enabled: <code>{sso_settings["enableMultipleSamlConfigs"]}</code></li>
        <li>{status_badge("INFO")} Login with Salesforce credentials disabled: <code>{sso_settings["isLoginWithSalesforceCredentialsDisabled"]}</code></li>
      </ul>
    </div>
  </div>

  <h2>Checks</h2>
  <ul class="check-list">
    {''.join(f'<li>{status_badge(check["status"])} {html.escape(check["message"])}' + (f' <code>{check["value"]}</code>' if "value" in check else f' [{check["count"]}]' if "count" in check else '') + '</li>' for check in checks)}
  </ul>

  <h2>SSO Signal History</h2>
  <ul>
    <li>LoginHistory rows sampled: {sso_signal_analysis["sampleSize"]}</li>
    <li>Rows marked as SSO via <code>AuthenticationServiceId</code>: {sso_signal_analysis["ssoLoginCount"]}</li>
    <li><code>AuthMethodReference</code> field available: {sso_signal_analysis["fieldAvailability"]["authMethodReference"]}</li>
    <li>ACR context reference field available: {sso_signal_analysis["fieldAvailability"]["acrContextClassReference"]}{' (' + html.escape(sso_signal_analysis["fieldAvailability"]["acrFieldName"]) + ')' if sso_signal_analysis["fieldAvailability"]["acrFieldName"] else ''}</li>
    <li>Rows with AMR values: {sso_signal_analysis["rowsWithAuthMethodReference"]}</li>
    <li>Rows with phishing-resistant matches: {sso_signal_analysis["phishingResistantMatchCount"]}</li>
    <li>Rows with standard MFA matches: {sso_signal_analysis["standardMatchCount"]}</li>
    <li>Rows with weak/no MFA matches: {sso_signal_analysis["weakOrNoMfaMatchCount"]}</li>
  </ul>
  <div class="card">
    <h3>Observed AMR Codes</h3>
    {("<ul>" + ''.join(f'<li>{status_badge(code["status"])} <code>{html.escape(code["code"])}</code> observed {code["count"]} time(s) -> {html.escape(code["classification"])}</li>' for code in sso_signal_analysis["observedCodes"]) + "</ul>") if sso_signal_analysis["observedCodes"] else '<div class="muted">No AMR codes were returned in the sampled LoginHistory rows.</div>'}
  </div>
  <details class="card collapsible">
    <summary><span class="summary-title">Recent Rows With SSO Signal Detail <span class="summary-hint">(please expand for details)</span></span><span class="summary-count">{len(sso_signal_analysis["signalRows"])} row(s)</span></summary>
    <div class="collapsible-body">
    <ul>
      {render_signal_rows()}
    </ul>
    </div>
  </details>

  <h2>Non-SSO Verification History</h2>
  <ul>
    <li>VerificationHistory rows sampled: {non_sso_verification_analysis["sampleSize"]}</li>
    <li>Non-SSO verification rows retained: {non_sso_verification_analysis["nonSsoVerificationCount"]}</li>
    <li>Rows with phishing-resistant methods: {non_sso_verification_analysis["phishingResistantCount"]}</li>
    <li>Rows with standard MFA methods: {non_sso_verification_analysis["standardCount"]}</li>
    <li>Rows with weak or recovery methods: {non_sso_verification_analysis["weakOrRecoveryCount"]}</li>
  </ul>
  <div class="card">
    <h3>Observed Non-SSO MFA Methods</h3>
    {("<ul>" + ''.join(f'<li>{status_badge(item["status"])} <code>{html.escape(item["method"])}</code> ({html.escape(item["label"])}) observed {item["count"]} time(s) -> {html.escape(item["classification"])}</li>' for item in non_sso_verification_analysis["observedMethods"]) + "</ul>") if non_sso_verification_analysis["observedMethods"] else '<div class="muted">No non-SSO verification methods were returned in the sampled VerificationHistory rows.</div>'}
  </div>
  <details class="card collapsible">
    <summary><span class="summary-title">Recent Non-SSO Verification Rows <span class="summary-hint">(please expand for details)</span></span><span class="summary-count">{len(non_sso_verification_analysis["verificationRows"])} row(s)</span></summary>
    <div class="collapsible-body">
    <ul>
      {render_verification_rows()}
    </ul>
    </div>
  </details>

  <h2>User Summary</h2>
  <ul>
    <li>Active internal users: {summary["activeInternalUserCount"]}</li>
    <li>Privileged internal users: {summary["privilegedInternalUserCount"]}</li>
    <li>Users with bypass assignments: {summary["usersWithBypassAssignments"]}</li>
    <li>Users with permission-based UI MFA: {summary["usersWithPermissionBasedUiMfa"]}</li>
    <li>SAML SSO configs: {summary["samlConfigCount"]}</li>
    <li>{html.escape('Per-user MFA methods visible: ' + str(summary['usersWithVisibleMfaMethods']) if mfa_methods_access['available'] else 'Per-user MFA methods unavailable: ' + mfa_methods_access['reason'])}</li>
  </ul>

  <h2>Users</h2>
  <details class="card collapsible">
    <summary><span class="summary-title">Privileged Users <span class="summary-hint">(please expand for details)</span></span><span class="summary-count">{len(privileged)} user(s)</span></summary>
    <div class="collapsible-body">
    {''.join(f'<div><strong>{html.escape(first_name_only(user["name"]))}</strong> &lt;{html.escape(user["username"])}&gt;'
             + ('<div class="muted">Available MFA methods: ' + html.escape(', '.join(user["availableMfaMethods"]) if user["availableMfaMethods"] else 'none visible') + '</div>' if mfa_methods_access["available"] else '')
             + item_list(user["privilegeReasons"]) + '</div>' for user in privileged) or '<div class="muted">No privileged users in the displayed slice.</div>'}
    </div>
  </details>
  <details class="card collapsible">
    <summary><span class="summary-title">Users With MFA Bypass Assignments <span class="summary-hint">(please expand for details)</span></span><span class="summary-count">{len(bypass_users)} user(s)</span></summary>
    <div class="collapsible-body">
    {''.join(f'<div><strong>{html.escape(first_name_only(user["name"]))}</strong> &lt;{html.escape(user["username"])}&gt;'
             + ('<div class="muted">Available MFA methods: ' + html.escape(', '.join(user["availableMfaMethods"]) if user["availableMfaMethods"] else 'none visible') + '</div>' if mfa_methods_access["available"] else '')
             + item_list(user["bypassMfaAssignments"]) + '</div>' for user in bypass_users) or '<div class="muted">No bypass-assigned users in the displayed slice.</div>'}
    </div>
  </details>
  <details class="card collapsible">
    <summary><span class="summary-title">Users Not Covered If Org-Wide UI MFA Is Off <span class="summary-hint">(please expand for details)</span></span><span class="summary-count">{len(uncovered)} user(s)</span></summary>
    <div class="collapsible-body">
    {''.join(f'<div><strong>{html.escape(first_name_only(user["name"]))}</strong> &lt;{html.escape(user["username"])}&gt;'
             + ('<div class="muted">Available MFA methods: ' + html.escape(', '.join(user["availableMfaMethods"]) if user["availableMfaMethods"] else 'none visible') + '</div>' if mfa_methods_access["available"] else '')
             + '</div>' for user in uncovered) or '<div class="muted">No uncovered users in the displayed slice.</div>'}
    </div>
  </details>

  <h2>Manual Review</h2>
  <ul>
    {''.join(f'<li><strong>{html.escape(item["topic"])}:</strong> {html.escape(item["reason"])}</li>' for item in manual_review_items)}
  </ul>
{resolutions_html}
</body>
</html>
"""


def escape_soql_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def curl_json(url: str, access_token: str) -> Any:
    completed = subprocess.run(
        [
            "curl",
            "-k",
            "-s",
            "-H",
            f"Authorization: Bearer {access_token}",
            url,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SfCommandError(
            f"curl request failed for {url}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def query_all_records_rest(org_info: dict[str, Any], soql: str) -> list[dict[str, Any]]:
    base_url = org_info["instanceUrl"].rstrip("/")
    url = f"{base_url}/services/data/v{API_VERSION}/query?q={urllib.parse.quote(soql)}"
    records: list[dict[str, Any]] = []

    while url:
        payload = curl_json(url, org_info["accessToken"])
        if isinstance(payload, list):
            message = payload[0].get("message", "Unknown REST query error.")
            raise ValueError(message)
        records.extend(payload.get("records", []))
        next_records_url = payload.get("nextRecordsUrl")
        url = f"{base_url}{next_records_url}" if next_records_url else None

    return records


def query_manage_two_factor_access(org_info: dict[str, Any]) -> dict[str, Any]:
    username = org_info.get("username")
    if not username:
        return {
            "hasAccess": False,
            "reason": "Could not determine current username for MFA API access check.",
        }

    escaped_username = escape_soql_literal(username)
    current_user_rows = query_records(
        org_info["alias"],
        (
            "SELECT Id, Username, Profile.PermissionsManageTwoFactor "
            f"FROM User WHERE Username = '{escaped_username}'"
        ),
    )
    permission_set_rows = query_records(
        org_info["alias"],
        (
            "SELECT PermissionSet.Name, PermissionSet.Label "
            "FROM PermissionSetAssignment "
            f"WHERE Assignee.Username = '{escaped_username}' "
            "AND PermissionSet.PermissionsManageTwoFactor = true"
        ),
    )

    profile_access = bool(
        current_user_rows
        and (current_user_rows[0].get("Profile") or {}).get("PermissionsManageTwoFactor")
    )
    permission_set_access = bool(permission_set_rows)
    granted_by = []
    if profile_access:
        granted_by.append("Profile")
    if permission_set_access:
        granted_by.extend(
            [
                row.get("PermissionSet", {}).get("Label")
                or row.get("PermissionSet", {}).get("Name")
                or "Permission Set"
                for row in permission_set_rows
            ]
        )

    has_access = profile_access or permission_set_access
    return {
        "hasAccess": has_access,
        "reason": None
        if has_access
        else "Current querying user does not have Manage MFA in API (PermissionsManageTwoFactor).",
        "grantedBy": granted_by,
    }


def fetch_two_factor_methods(
    org_info: dict[str, Any], user_ids: list[str]
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    access_info = query_manage_two_factor_access(org_info)
    if not access_info["hasAccess"]:
        return {}, {
            "available": False,
            "reason": access_info["reason"],
            "grantedBy": access_info.get("grantedBy", []),
        }

    object_list = curl_json(
        f"{org_info['instanceUrl'].rstrip('/')}/services/data/v{API_VERSION}/sobjects/",
        org_info["accessToken"],
    )
    sobject_names = {item.get("name") for item in object_list.get("sobjects", [])}
    if "TwoFactorMethodsInfo" not in sobject_names:
        return {}, {
            "available": False,
            "reason": "TwoFactorMethodsInfo is not exposed in this org's REST sObject describe.",
            "grantedBy": access_info.get("grantedBy", []),
        }

    if not user_ids:
        return {}, {"available": True, "reason": None, "grantedBy": access_info.get("grantedBy", [])}

    fields_variants = [
        [
            "UserId",
            "HasBuiltInAuthenticator",
            "HasSalesforceAuthenticator",
            "HasTotp",
            "HasU2F",
            "HasSecurityKey",
            "HasUserVerifiedEmailAddress",
            "HasUserVerifiedMobileNumber",
            "HasVerifiedMobileNumber",
            "HasTempCode",
        ],
        [
            "UserId",
            "HasSalesforceAuthenticator",
            "HasTotp",
            "HasU2F",
            "HasSecurityKey",
            "HasUserVerifiedEmailAddress",
            "HasUserVerifiedMobileNumber",
            "HasVerifiedMobileNumber",
            "HasTempCode",
        ],
    ]

    records: list[dict[str, Any]] = []
    last_error: str | None = None
    base_url = org_info["instanceUrl"].rstrip("/")

    for fields in fields_variants:
        try:
            records = []
            for index in range(0, len(user_ids), 100):
                chunk = user_ids[index : index + 100]
                user_id_filter = ", ".join(f"'{escape_soql_literal(user_id)}'" for user_id in chunk)
                soql = (
                    f"SELECT {', '.join(fields)} FROM TwoFactorMethodsInfo "
                    f"WHERE UserId IN ({user_id_filter})"
                )
                url = f"{base_url}/services/data/v{API_VERSION}/query?q={urllib.parse.quote(soql)}"
                payload = curl_json(url, org_info["accessToken"])
                if isinstance(payload, list):
                    message = payload[0].get("message", "Unknown TwoFactorMethodsInfo error.")
                    raise ValueError(message)
                records.extend(payload.get("records", []))
            break
        except ValueError as exc:
            last_error = str(exc)
            continue

    if last_error and not records:
        return {}, {
            "available": False,
            "reason": f"TwoFactorMethodsInfo query failed: {last_error}",
            "grantedBy": access_info.get("grantedBy", []),
        }

    methods_by_user: dict[str, list[str]] = {}
    for record in records:
        methods = []
        if record.get("HasBuiltInAuthenticator"):
            methods.append("Built-in authenticator")
        if record.get("HasSalesforceAuthenticator"):
            methods.append("Salesforce Authenticator")
        if record.get("HasTotp"):
            methods.append("OTP app (TOTP)")
        if record.get("HasSecurityKey") or record.get("HasU2F"):
            methods.append("Hardware key")
        if record.get("HasUserVerifiedEmailAddress"):
            methods.append("Email OTP")
        if record.get("HasUserVerifiedMobileNumber") or record.get("HasVerifiedMobileNumber"):
            methods.append("SMS / mobile OTP")
        if record.get("HasTempCode"):
            methods.append("Temporary verification code")
        methods_by_user[record["UserId"]] = dedupe(methods)

    return methods_by_user, {
        "available": True,
        "reason": None,
        "grantedBy": access_info.get("grantedBy", []),
    }


def build_report(org_alias: str, repo_root: Path, large_org_sample: bool = False) -> dict[str, Any]:
    progress(f"Starting audit for org '{org_alias}'")
    progress("Loading org connection details")
    org_info = run_sf_json(["org", "display", "--target-org", org_alias])["result"]
    org_info["alias"] = org_alias
    progress("Loading org-level MFA and SSO settings")
    security_settings = retrieve_security_settings(org_alias, repo_root)
    internal_where = internal_user_where_clause()
    internal_where_sampled = internal_user_where_clause(
        include_license_filter=False, selective_user_type=True
    )

    sampling: dict[str, Any] | None = None
    if large_org_sample:
        progress("Querying sampled internal-user set")
        user_rows = query_records(
            org_alias,
            textwrap.dedent(
                f"""
                SELECT {USER_SELECT_FIELDS}
                FROM User
                WHERE {internal_where_sampled}
                LIMIT {USER_QUERY_LIMIT}
                """
            ).strip(),
        )

        sampled_user_ids = [row["Id"] for row in user_rows if row.get("Id")]
        assignment_rows: list[dict[str, Any]] = []
        if sampled_user_ids:
            progress("Querying permission set assignments for sampled users")
            for index in range(0, len(sampled_user_ids), 100):
                chunk = sampled_user_ids[index : index + 100]
                assignee_filter = ", ".join(f"'{escape_soql_literal(user_id)}'" for user_id in chunk)
                assignment_rows.extend(
                    query_records(
                        org_alias,
                        textwrap.dedent(
                            f"""
                            SELECT AssigneeId, Assignee.Name, Assignee.Username,
                                   PermissionSet.Name, PermissionSet.Label, PermissionSet.IsOwnedByProfile,
                                   PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData,
                                   PermissionSet.PermissionsCustomizeApplication, PermissionSet.PermissionsAuthorApex,
                                   PermissionSet.PermissionsForceTwoFactor, PermissionSet.PermissionsBypassMFAForUiLogins
                            FROM PermissionSetAssignment
                            WHERE PermissionSet.IsOwnedByProfile = false
                              AND AssigneeId IN ({assignee_filter})
                              AND (
                                PermissionSet.PermissionsModifyAllData = true
                                OR PermissionSet.PermissionsViewAllData = true
                                OR PermissionSet.PermissionsCustomizeApplication = true
                                OR PermissionSet.PermissionsAuthorApex = true
                                OR PermissionSet.PermissionsForceTwoFactor = true
                                OR PermissionSet.PermissionsBypassMFAForUiLogins = true
                              )
                            """
                        ).strip(),
                    )
                )
        active_internal_user_count: int | None = None
        sampling = {
            "enabled": True,
            "userQueryLimit": USER_QUERY_LIMIT,
            "userRenderLimit": USER_RENDER_LIMIT,
        }
    else:
        progress("Counting active internal users")
        active_internal_user_count = query_total_size(
            org_alias,
            f"SELECT COUNT() FROM User WHERE {internal_where}",
        )

        progress("Querying targeted users with risky profile permissions")
        user_rows = query_all_records_rest(
            org_info,
            textwrap.dedent(
                f"""
                SELECT {USER_SELECT_FIELDS}
                FROM User
                WHERE {internal_where}
                  AND (
                    Profile.Name = 'System Administrator'
                    OR Profile.PermissionsModifyAllData = true
                    OR Profile.PermissionsViewAllData = true
                    OR Profile.PermissionsCustomizeApplication = true
                    OR Profile.PermissionsAuthorApex = true
                    OR Profile.PermissionsForceTwoFactor = true
                    OR Profile.PermissionsBypassMFAForUiLogins = true
                  )
                ORDER BY Name
                LIMIT {USER_QUERY_LIMIT}
                """
            ).strip(),
        )

        progress("Querying permission set assignments relevant to MFA and privileged access")
        assignment_rows = query_all_records_rest(
            org_info,
            textwrap.dedent(
                f"""
                SELECT AssigneeId, Assignee.Name, Assignee.Username,
                       PermissionSet.Name, PermissionSet.Label, PermissionSet.IsOwnedByProfile,
                       PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData,
                       PermissionSet.PermissionsCustomizeApplication, PermissionSet.PermissionsAuthorApex,
                       PermissionSet.PermissionsForceTwoFactor, PermissionSet.PermissionsBypassMFAForUiLogins
                FROM PermissionSetAssignment
                WHERE PermissionSet.IsOwnedByProfile = false
                  AND (
                    PermissionSet.PermissionsModifyAllData = true
                    OR PermissionSet.PermissionsViewAllData = true
                    OR PermissionSet.PermissionsCustomizeApplication = true
                    OR PermissionSet.PermissionsAuthorApex = true
                    OR PermissionSet.PermissionsForceTwoFactor = true
                    OR PermissionSet.PermissionsBypassMFAForUiLogins = true
                  )
                ORDER BY Assignee.Name
                LIMIT {USER_QUERY_LIMIT}
                """
            ).strip(),
        )

    progress("Checking for SAML SSO configurations")
    saml_metadata = list_metadata(org_alias, "SamlSsoConfig")
    saml_configs = saml_metadata.get("result", []) if isinstance(saml_metadata.get("result"), list) else []
    sso_signal_analysis = fetch_recent_login_history_signal_analysis(org_alias)
    non_sso_verification_analysis = fetch_recent_non_sso_verification_analysis(org_alias)

    progress("Classifying internal users, privileged users, and MFA exceptions")
    assignments_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in assignment_rows:
        assignee_id = row.get("AssigneeId")
        if assignee_id:
            assignments_by_user[assignee_id].append(row)

    if not large_org_sample:
        assignment_user_ids = sorted(
            {row.get("AssigneeId") for row in assignment_rows if row.get("AssigneeId")}
        )
        existing_user_ids = {row.get("Id") for row in user_rows if row.get("Id")}
        additional_user_rows = fetch_user_rows_by_ids(
            org_alias,
            [user_id for user_id in assignment_user_ids if user_id not in existing_user_ids],
        )
        user_rows.extend(additional_user_rows)

    internal_users: list[dict[str, Any]] = []
    privileged_users: list[dict[str, Any]] = []
    users_with_bypass: list[dict[str, Any]] = []
    users_with_permission_mfa: list[dict[str, Any]] = []
    uncovered_internal_users: list[dict[str, Any]] = []
    covered_user_ids: set[str] = set()
    privileged_user_ids: set[str] = set()
    bypass_user_ids: set[str] = set()

    org_mfa_enabled = security_settings["sessionSettings"]["enableMFADirectUILoginOptIn"] is True

    for user in user_rows:
        if not is_internal_user(user):
            continue

        assignment_subset = assignments_by_user.get(user["Id"], [])
        mfa_assignments = collect_mfa_assignments(user, assignment_subset)
        reasons = collect_privileged_reasons(user, assignment_subset)

        internal_user = {
            "id": user["Id"],
            "name": user.get("Name"),
            "username": user.get("Username"),
            "userType": user.get("UserType"),
            "profile": (user.get("Profile") or {}).get("Name"),
            "forceMfaAssignments": mfa_assignments["force_mfa"],
            "bypassMfaAssignments": mfa_assignments["bypass_mfa"],
        }
        internal_users.append(internal_user)

        if reasons:
            privileged_user_ids.add(user["Id"])
            privileged_users.append({**internal_user, "privilegeReasons": reasons})

        if mfa_assignments["bypass_mfa"]:
            bypass_user_ids.add(user["Id"])
            users_with_bypass.append(internal_user)

        if mfa_assignments["force_mfa"]:
            covered_user_ids.add(user["Id"])
            users_with_permission_mfa.append(internal_user)

    if not org_mfa_enabled and large_org_sample:
        for user in user_rows:
            if user["Id"] in covered_user_ids or not is_internal_user(user):
                continue
            uncovered_internal_users.append(
                {
                    "id": user["Id"],
                    "name": user.get("Name"),
                    "username": user.get("Username"),
                    "userType": user.get("UserType"),
                    "profile": (user.get("Profile") or {}).get("Name"),
                    "forceMfaAssignments": [],
                    "bypassMfaAssignments": [],
                }
            )
    elif not org_mfa_enabled:
        progress("Querying a capped internal-user sample for uncovered-user detail")
        uncovered_sample_rows = query_records(
            org_alias,
            textwrap.dedent(
                f"""
                SELECT {USER_SELECT_FIELDS}
                FROM User
                WHERE {internal_where_sampled}
                LIMIT {USER_QUERY_LIMIT}
                """
            ).strip(),
        )
        for user in uncovered_sample_rows:
            if user["Id"] in covered_user_ids or not is_internal_user(user):
                continue
            uncovered_internal_users.append(
                {
                    "id": user["Id"],
                    "name": user.get("Name"),
                    "username": user.get("Username"),
                    "userType": user.get("UserType"),
                    "profile": (user.get("Profile") or {}).get("Name"),
                    "forceMfaAssignments": [],
                    "bypassMfaAssignments": [],
                }
            )

    progress("Checking per-user MFA methods availability")
    methods_by_user, methods_access = fetch_two_factor_methods(
        org_info,
        dedupe([user["id"] for user in internal_users] + [user["id"] for user in uncovered_internal_users]),
    )

    for user_list in (
        internal_users,
        privileged_users,
        users_with_bypass,
        users_with_permission_mfa,
        uncovered_internal_users,
    ):
        for user in user_list:
            user["availableMfaMethods"] = methods_by_user.get(user["id"], [])

    progress("Evaluating compliance checks")
    checks = [
        {
            "id": "direct_ui_mfa_enabled",
            "status": status_for_boolean(security_settings["sessionSettings"]["enableMFADirectUILoginOptIn"]),
            "message": "Require MFA for all direct UI logins",
            "value": security_settings["sessionSettings"]["enableMFADirectUILoginOptIn"],
        },
        {
            "id": "built_in_authenticator_enabled",
            "status": status_for_boolean(security_settings["sessionSettings"]["enableBuiltInAuthenticator"]),
            "message": "Built-in authenticator allowed",
            "value": security_settings["sessionSettings"]["enableBuiltInAuthenticator"],
        },
        {
            "id": "security_key_enabled",
            "status": status_for_boolean(security_settings["sessionSettings"]["enableU2F"]),
            "message": "Physical security key (U2F/WebAuthn) allowed",
            "value": security_settings["sessionSettings"]["enableU2F"],
        },
    ]

    if users_with_bypass:
        checks.append(
            {
                "id": "bypass_assignments",
                "status": "FAIL",
                "message": "Users with MFA bypass / waiver assignments detected",
                "count": len(users_with_bypass),
            }
        )
    else:
        checks.append(
            {
                "id": "bypass_assignments",
                "status": "PASS",
                "message": "No MFA bypass / waiver assignments detected",
                "count": 0,
            }
        )

    if privileged_users and not (
        security_settings["sessionSettings"]["enableBuiltInAuthenticator"]
        or security_settings["sessionSettings"]["enableU2F"]
    ):
        checks.append(
            {
                "id": "privileged_user_method_readiness",
                "status": "FAIL",
                "message": "Privileged users exist but phishing-resistant MFA methods are not enabled in org settings",
                "count": len(privileged_users),
            }
        )
    else:
        checks.append(
            {
                "id": "privileged_user_method_readiness",
                "status": "PASS" if privileged_users else "INFO",
                "message": (
                    "Privileged users exist and the org allows at least one phishing-resistant MFA method"
                    if privileged_users
                    else "No privileged internal users detected by the audited permission criteria"
                ),
                "count": len(privileged_users),
            }
        )

    sso_enabled = security_settings["singleSignOnSettings"]["enableSamlLogin"] or bool(saml_configs)
    checks.append(
        {
            "id": "sso_signal_validation",
            "status": "WARN" if sso_enabled else "PASS",
            "message": (
                "SSO is configured; review sampled LoginHistory AMR signals and validate all IdP AMR/ACR responses"
                if sso_enabled
                else "No SAML SSO configuration detected in audited metadata"
            ),
            "samlConfigCount": len(saml_configs),
        }
    )

    progress("Assembling final report")
    report = {
        "org": {
            "alias": org_alias,
            "username": org_info.get("username"),
            "orgId": org_info.get("id") or org_info.get("orgId"),
            "instanceUrl": org_info.get("instanceUrl"),
            "isSandbox": org_info.get("isSandbox"),
        },
        "run": {
            "generatedAt": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z%z")
        },
        "enforcementTimeline": {
            "sandbox": {
                "allUiLoginsMfaStarts": "2026-06-22",
                "privilegedUsersPhishingResistantMfaStarts": "2026-06-22",
            },
            "production": {
                "privilegedUsersPhishingResistantMfaStarts": "2026-07-01",
                "allUiLoginsMfaStarts": "2026-07-20",
            },
            "notes": [
                "Salesforce rolled these changes out in waves during the listed start windows.",
                "Privileged users include System Administrator users and anyone with Modify All Data, View All Data, Customize Application, or Author Apex.",
                (
                    f"User-based analysis in this report is sampled from the first {USER_QUERY_LIMIT} queried users, and rendered user detail sections show the first {USER_RENDER_LIMIT} rows."
                    if large_org_sample
                    else f"Risk-oriented user queries are capped to the first {USER_QUERY_LIMIT} rows; all matched users in that set are rendered (no display cap), so user detail counts match the scatterplot."
                ),
            ],
        },
        "settings": security_settings,
        "checks": checks,
        "summary": {
            "activeInternalUserCount": (
                len(internal_users) if large_org_sample else int(active_internal_user_count or 0)
            ),
            "privilegedInternalUserCount": len(privileged_user_ids),
            "usersWithBypassAssignments": len(bypass_user_ids),
            "usersWithPermissionBasedUiMfa": len(covered_user_ids),
            "uncoveredInternalUsersIfOrgSwitchOff": (
                len(uncovered_internal_users)
                if large_org_sample
                else (max(int(active_internal_user_count or 0) - len(covered_user_ids), 0) if not org_mfa_enabled else 0)
            ),
            "samlConfigCount": len(saml_configs),
            "usersWithVisibleMfaMethods": sum(1 for user in internal_users if user.get("availableMfaMethods")),
        },
        "details": {
            "privilegedUsers": privileged_users,
            "usersWithBypassAssignments": users_with_bypass,
            "usersWithPermissionBasedUiMfa": users_with_permission_mfa,
            "uncoveredInternalUsersIfOrgSwitchOff": uncovered_internal_users,
            "samlConfigs": [item.get("fullName") for item in saml_configs],
            "ssoLoginSignalAnalysis": sso_signal_analysis,
            "nonSsoVerificationAnalysis": non_sso_verification_analysis,
            "mfaMethodsAccess": methods_access,
        },
        "manualReview": [
            {
                "topic": "SSO MFA / phishing-resistant claim validation",
                "requiredWhen": sso_enabled,
                "reason": "The report now samples recent LoginHistory AMR values, but you should still validate every SSO path and full IdP assertion behavior, especially where ACR is not exposed in LoginHistory.",
            },
            {
                "topic": "Actual user MFA method enrollment",
                "requiredWhen": True,
                "reason": "The standard sf CLI surfaces org settings and permission assignments cleanly, but user-level registered MFA methods are not consistently queryable through stable CLI-accessible objects.",
            },
        ],
    }
    if sampling is not None:
        report["sampling"] = sampling

    return report


def render_markdown_report(
    report: dict[str, Any], scatterplot_image_path: str | None = None
) -> str:
    org = report["org"]
    run = report["run"]
    summary = report["summary"]
    settings = report["settings"]
    sampling = report.get("sampling", {"enabled": False})
    session_settings = settings["sessionSettings"]
    sso_settings = settings["singleSignOnSettings"]
    mfa_methods_access = report["details"]["mfaMethodsAccess"]
    sso_signal_analysis = report["details"].get(
        "ssoLoginSignalAnalysis",
        {
            "sampleSize": 0,
            "ssoLoginCount": 0,
            "rowsWithAuthMethodReference": 0,
            "rowsWithAcrContextReference": 0,
            "phishingResistantMatchCount": 0,
            "standardMatchCount": 0,
            "weakOrNoMfaMatchCount": 0,
            "unrecognizedSignalCount": 0,
            "missingSignalCount": 0,
            "fieldAvailability": {
                "authMethodReference": False,
                "acrContextClassReference": False,
                "acrFieldName": None,
            },
            "observedCodes": [],
            "signalRows": [],
        },
    )
    non_sso_verification_analysis = report["details"].get(
        "nonSsoVerificationAnalysis",
        {
            "sampleSize": 0,
            "nonSsoVerificationCount": 0,
            "phishingResistantCount": 0,
            "standardCount": 0,
            "weakOrRecoveryCount": 0,
            "unrecognizedCount": 0,
            "observedMethods": [],
            "verificationRows": [],
        },
    )
    lines: list[str] = []
    check_statuses = [check["status"] for check in report["checks"]]
    overall_status, overall_label = overall_readiness(check_statuses)
    issue_points = build_issue_scatterplot_points(report)

    lines.append("# Salesforce MFA Audit Report")
    lines.append(f"_Run at: {run['generatedAt']}_")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(
        f"> **Overall readiness:** {status_icon(overall_status)} **{overall_label}**"
    )
    lines.append(build_section_score(check_statuses))
    lines.append("")
    lines.append(
        f"- **Primary takeaway:** {summary['privilegedInternalUserCount']} privileged internal user(s) "
        f"must be ready for phishing-resistant MFA, and {summary['usersWithBypassAssignments']} bypass assignment(s) were detected."
    )
    lines.append(
        f"- **Coverage snapshot:** {summary['activeInternalUserCount']} active internal user(s), "
        f"{summary['usersWithPermissionBasedUiMfa']} user(s) with permission-based UI MFA, "
        f"{summary['uncoveredInternalUsersIfOrgSwitchOff']} user(s) not covered if org-wide UI MFA is off."
    )
    if mfa_methods_access["available"]:
        lines.append(
            f"- **Per-user MFA methods:** visible for {summary['usersWithVisibleMfaMethods']} internal user(s)."
        )
    else:
        lines.append(
            f"- **Per-user MFA methods:** unavailable. {mfa_methods_access['reason']}"
        )
    lines.append(
        f"- **SSO snapshot:** {summary['samlConfigCount']} SAML config(s) detected."
    )
    if sampling.get("enabled"):
        lines.append(
            "- **Sampling note:** "
            f"User-based counts and user lists in this report are based on the first {sampling.get('userQueryLimit')} queried users; "
            f"displayed user sections are capped to {sampling.get('userRenderLimit')} rows."
        )
    lines.append("")
    lines.append("## Org")
    lines.append(f"- **Alias:** `{org['alias']}`")
    lines.append(f"- **Username:** `{org['username']}`")
    lines.append(f"- **Instance:** `{org['instanceUrl']}`")
    lines.append("")

    add_section_header(lines, "Issue Scatterplot", ["WARN"])
    lines.append(
        "Point positions use a log-scaled Y-axis so a very large category does not visually flatten the smaller issue categories. Raw counts are still shown inside each point and in the summary below."
    )
    lines.append("")
    if scatterplot_image_path:
        lines.append(f"![MyOrg MFA issue scatterplot]({scatterplot_image_path})")
    else:
        lines.append(
            "_Scatterplot image is generated when you run the report with `--markdown-file`._"
        )
    lines.append("")
    for point in issue_points:
        lines.append(f"- **{point['label']}:** {point['count']} occurrence(s) - {point['description']}")
    lines.append("")

    config_statuses = [
        status_for_boolean(session_settings["enableMFADirectUILoginOptIn"]),
        status_for_boolean(session_settings["enableBuiltInAuthenticator"]),
        status_for_boolean(session_settings["enableU2F"]),
        "WARN" if sso_settings["enableSamlLogin"] else "PASS",
        "INFO",
        "INFO",
    ]
    add_section_header(lines, "Configurations", config_statuses)
    lines.append("- **Security settings**")
    lines.append(
        f"  - {status_icon(status_for_boolean(session_settings['enableMFADirectUILoginOptIn']))} "
        f"Direct UI MFA required: `{session_settings['enableMFADirectUILoginOptIn']}`"
    )
    lines.append(
        f"  - {status_icon(status_for_boolean(session_settings['enableBuiltInAuthenticator']))} "
        f"Built-in authenticator enabled: `{session_settings['enableBuiltInAuthenticator']}`"
    )
    lines.append(
        f"  - {status_icon(status_for_boolean(session_settings['enableU2F']))} "
        f"Security key / U2F enabled: `{session_settings['enableU2F']}`"
    )
    lines.append(
        f"  - {status_icon('INFO')} Lightning Login enabled: `{session_settings['enableLightningLogin']}`"
    )
    lines.append(
        f"  - {status_icon('INFO')} SMS identity enabled: `{session_settings['enableSMSIdentity']}`"
    )
    lines.append("- **Single sign-on settings**")
    lines.append(
        f"  - {status_icon('WARN' if sso_settings['enableSamlLogin'] else 'INFO')} "
        f"SAML login enabled: `{sso_settings['enableSamlLogin']}`"
    )
    lines.append(
        f"  - {status_icon('INFO')} Multiple SAML configs enabled: `{sso_settings['enableMultipleSamlConfigs']}`"
    )
    lines.append(
        f"  - {status_icon('INFO')} Login with Salesforce credentials disabled: "
        f"`{sso_settings['isLoginWithSalesforceCredentialsDisabled']}`"
    )

    add_section_header(lines, "Checks", [check["status"] for check in report["checks"]])
    for check in report["checks"]:
        value_suffix = ""
        if "value" in check:
            value_suffix = f" [{check['value']}]"
        elif "count" in check:
            value_suffix = f" [{check['count']}]"
        lines.append(
            f"- {status_icon(check['status'])} **{check['status']}**: {check['message']}{value_suffix}"
        )

    add_section_header(
        lines,
        "SSO Signal History",
        summarize_sso_signal_statuses(
            sso_signal_analysis,
            sso_settings["enableSamlLogin"] or bool(report["details"].get("samlConfigs")),
        ),
    )
    lines.append(
        f"- LoginHistory rows sampled: {sso_signal_analysis['sampleSize']}"
    )
    lines.append(
        f"- Rows marked as SSO via `AuthenticationServiceId`: {sso_signal_analysis['ssoLoginCount']}"
    )
    lines.append(
        f"- `AuthMethodReference` field available: `{sso_signal_analysis['fieldAvailability']['authMethodReference']}`"
    )
    if sso_signal_analysis["fieldAvailability"]["acrContextClassReference"]:
        lines.append(
            "- ACR context reference field available: "
            f"`True` (`{sso_signal_analysis['fieldAvailability']['acrFieldName']}`)"
        )
    else:
        lines.append("- ACR context reference field available: `False`")
    lines.append(
        f"- Rows with AMR values: {sso_signal_analysis['rowsWithAuthMethodReference']}"
    )
    lines.append(
        f"- Rows with phishing-resistant matches: {sso_signal_analysis['phishingResistantMatchCount']}"
    )
    lines.append(
        f"- Rows with standard MFA matches: {sso_signal_analysis['standardMatchCount']}"
    )
    lines.append(
        f"- Rows with weak/no MFA matches: {sso_signal_analysis['weakOrNoMfaMatchCount']}"
    )
    lines.append("")
    lines.append("### Observed AMR Codes")
    if sso_signal_analysis["observedCodes"]:
        for code in sso_signal_analysis["observedCodes"]:
            lines.append(
                f"- {status_icon(code['status'])} `{code['code']}` observed {code['count']} time(s) -> {code['classification']}"
            )
    else:
        lines.append("- No AMR codes were returned in the sampled LoginHistory rows.")
    lines.append("")
    lines.append("### Recent Rows With SSO Signal Detail")
    if sso_signal_analysis["signalRows"]:
        for row in sso_signal_analysis["signalRows"]:
            identity = display_user_identity(row.get("userName"), row.get("username"), row.get("userId"))
            lines.append(
                f"- {status_icon(row['classificationStatus'])} `{row['loginTime']}` | {identity} | "
                f"{row.get('application') or 'Unknown application'} | "
                f"AMR: `{row.get('authMethodReference') or 'none'}` | "
                f"ACR: `{row.get('acrContextClassReference') or 'not available'}` | "
                f"Match: {row['classification']}"
            )
    else:
        lines.append(
            "- No recent LoginHistory rows in the 100-login sample exposed an AMR signal or an SSO-authentication service reference."
        )

    add_section_header(
        lines,
        "Non-SSO Verification History",
        summarize_non_sso_verification_statuses(non_sso_verification_analysis),
    )
    lines.append(
        f"- VerificationHistory rows sampled: {non_sso_verification_analysis['sampleSize']}"
    )
    lines.append(
        f"- Non-SSO verification rows retained: {non_sso_verification_analysis['nonSsoVerificationCount']}"
    )
    lines.append(
        f"- Rows with phishing-resistant methods: {non_sso_verification_analysis['phishingResistantCount']}"
    )
    lines.append(
        f"- Rows with standard MFA methods: {non_sso_verification_analysis['standardCount']}"
    )
    lines.append(
        f"- Rows with weak or recovery methods: {non_sso_verification_analysis['weakOrRecoveryCount']}"
    )
    lines.append("")
    lines.append("### Observed Non-SSO MFA Methods")
    if non_sso_verification_analysis["observedMethods"]:
        for item in non_sso_verification_analysis["observedMethods"]:
            lines.append(
                f"- {status_icon(item['status'])} `{item['method']}` ({item['label']}) observed {item['count']} time(s) -> {item['classification']}"
            )
    else:
        lines.append("- No non-SSO verification methods were returned in the sampled VerificationHistory rows.")
    lines.append("")
    lines.append("### Recent Non-SSO Verification Rows")
    if non_sso_verification_analysis["verificationRows"]:
        for row in non_sso_verification_analysis["verificationRows"]:
            identity = display_user_identity(row.get("userName"), row.get("username"), row.get("userId"))
            lines.append(
                f"- {status_icon(row['classificationStatus'])} `{row['verificationTime']}` | {identity} | "
                f"{row.get('application') or 'Unknown application'} | "
                f"Method: `{row.get('verificationMethod') or 'unknown'}` | "
                f"Label: {row.get('verificationMethodLabel') or 'Unknown'} | "
                f"Match: {row['classification']}"
            )
    else:
        lines.append(
            "- No recent non-SSO verification history rows were available in the sampled VerificationHistory data."
        )

    user_summary_statuses = [
        "WARN" if summary["privilegedInternalUserCount"] else "PASS",
        "FAIL" if summary["usersWithBypassAssignments"] else "PASS",
        "INFO" if summary["usersWithPermissionBasedUiMfa"] else "PASS",
        "WARN" if summary["uncoveredInternalUsersIfOrgSwitchOff"] else "PASS",
    ]
    add_section_header(lines, "User Summary", user_summary_statuses)
    lines.append(f"- Active internal users: {summary['activeInternalUserCount']}")
    lines.append(f"- Privileged internal users: {summary['privilegedInternalUserCount']}")
    lines.append(f"- Users with bypass assignments: {summary['usersWithBypassAssignments']}")
    lines.append(f"- Users with permission-based UI MFA: {summary['usersWithPermissionBasedUiMfa']}")
    lines.append(f"- SAML SSO configs: {summary['samlConfigCount']}")
    if mfa_methods_access["available"]:
        lines.append(f"- Users with visible MFA method detail: {summary['usersWithVisibleMfaMethods']}")
    else:
        lines.append(f"- Per-user MFA methods unavailable: {mfa_methods_access['reason']}")

    render_limit = USER_RENDER_LIMIT if sampling.get("enabled") else None
    privileged = report["details"]["privilegedUsers"][:render_limit]
    bypass_users = report["details"]["usersWithBypassAssignments"][:render_limit]
    uncovered = report["details"]["uncoveredInternalUsersIfOrgSwitchOff"][:render_limit]

    user_section_statuses = [
        "WARN" if privileged else "PASS",
        "FAIL" if bypass_users else "PASS",
        "WARN" if uncovered else "PASS",
    ]
    add_section_header(lines, "Users", user_section_statuses)

    if privileged:
        lines.append("### Privileged Users")
        for user in privileged:
            lines.append(f"- **{first_name_only(user['name'])}** `<{user['username']}>`")
            if mfa_methods_access["available"]:
                if user["availableMfaMethods"]:
                    lines.append(
                        f"  - Available MFA methods: {', '.join(user['availableMfaMethods'])}"
                    )
                else:
                    lines.append("  - Available MFA methods: none visible")
            for reason in user["privilegeReasons"]:
                lines.append(f"  - {reason}")

    if bypass_users:
        lines.append("")
        lines.append("### Users With MFA Bypass Assignments")
        for user in bypass_users:
            lines.append(f"- **{first_name_only(user['name'])}** `<{user['username']}>`")
            if mfa_methods_access["available"]:
                if user["availableMfaMethods"]:
                    lines.append(
                        f"  - Available MFA methods: {', '.join(user['availableMfaMethods'])}"
                    )
                else:
                    lines.append("  - Available MFA methods: none visible")
            for assignment in user["bypassMfaAssignments"]:
                lines.append(f"  - {assignment}")

    if uncovered:
        lines.append("")
        lines.append("### Users Not Covered If Org-Wide UI MFA Is Off")
        for user in uncovered:
            lines.append(f"- **{first_name_only(user['name'])}** `<{user['username']}>`")
            if mfa_methods_access["available"]:
                if user["availableMfaMethods"]:
                    lines.append(
                        f"  - Available MFA methods: {', '.join(user['availableMfaMethods'])}"
                    )
                else:
                    lines.append("  - Available MFA methods: none visible")

    manual_review_items = [item for item in report["manualReview"] if item["requiredWhen"]]
    add_section_header(lines, "Manual Review", ["WARN" for _ in manual_review_items] or ["PASS"])
    for item in manual_review_items:
        if item["requiredWhen"]:
            lines.append(f"- {item['topic']}: {item['reason']}")

    resolution_entries = build_resolution_entries(report["checks"])
    add_section_header(
        lines, "Resolutions", [entry["status"] for entry in resolution_entries] or ["PASS"]
    )
    if resolution_entries:
        lines.append(
            "Suggested primary and secondary fixes for the issues flagged in the executive summary."
        )
        lines.append("")
        for entry in resolution_entries:
            lines.append(f"- {status_icon(entry['status'])} **{entry['issue']}**")
            lines.append(f"  - **Primary:** {entry['primary']}")
            lines.append(f"  - **Secondary:** {entry['secondary']}")
    else:
        lines.append(
            "No outstanding issues from the executive summary checks - no resolutions required."
        )

    return "\n".join(lines)


def emit_human_report(report: dict[str, Any]) -> None:
    print(render_markdown_report(report))


# The Salesforce mark rendered as a glyph cloud, filled with "S" characters.
# "X" marks a filled cell in the template below.
_SALESFORCE_CLOUD = [
    "            XXXXX      XXXXXXX         ",
    "         XXXXXXXXXXXXXXXXXXXXXX        ",
    "       XXXXXXXXXXXXXXXXXXXXXXXXXX      ",
    "      XXXXXXXXXXXXXXXXXXXXXXXXXXXX     ",
    "       XXXXXXXXXXXXXXXXXXXXXXXXXX      ",
    "        XXXXXXXXXXXXXXXXXXXXXXXX       ",
    "         XXXX XXXXXX XXXXX XXXX        ",
]


def build_salesforce_cloud_rows(fill: str = "S") -> list[str]:
    """Render the Salesforce cloud mark as a glyph filled with ``fill``."""
    rows = [row.replace("X", fill) for row in _SALESFORCE_CLOUD]
    width = max(len(row) for row in rows)
    return [row.ljust(width) for row in rows]


_CLOUD_PAD = 3


def render_salesforce_logo_lines(pad: int = _CLOUD_PAD) -> list[str]:
    """Render the Salesforce mark as a blue cloud on a white background with
    the white "Salesforce" wordmark centered inside the cloud, mirroring the
    real logo. Returns ANSI-colored lines ready to print.
    """
    reset = "\033[0m"
    white_bg = "\033[48;5;231m"
    blue_bg = "\033[48;5;39m"  # approx Salesforce blue (#00A1E0)
    white_fg = "\033[38;5;231m"
    default_fg = "\033[39m"

    width = max(len(row) for row in _SALESFORCE_CLOUD)
    grid = [list(row.ljust(width)) for row in _SALESFORCE_CLOUD]

    word = "Salesforce"
    mid = len(grid) // 2
    start = (width - len(word)) // 2
    overlay = {start + i: char for i, char in enumerate(word)}

    def cell(y: int, x: int) -> tuple[str, str, str]:
        filled = grid[y][x] == "X"
        if y == mid and filled and x in overlay:
            return (blue_bg, white_fg, overlay[x])
        if filled:
            return (blue_bg, default_fg, " ")
        return (white_bg, default_fg, " ")

    total = width + pad * 2
    margin = f"{white_bg}{' ' * total}{reset}"
    lines = [margin]
    for y in range(len(grid)):
        cells = [(white_bg, default_fg, " ")] * pad
        cells += [cell(y, x) for x in range(width)]
        cells += [(white_bg, default_fg, " ")] * pad
        line = ""
        current_style = None
        for bg, fg, char in cells:
            style = bg + fg
            if style != current_style:
                line += style
                current_style = style
            line += char
        lines.append(line + reset)
    lines.append(margin)
    return lines


# Each glyph is drawn with its own letter: the M from "M"s, the F from "F"s,
# and the A from "A"s. "X" marks a filled cell in the template below.
_MFA_GLYPHS = {
    "M": [
        "X     X",
        "XX   XX",
        "X X X X",
        "X  X  X",
        "X     X",
        "X     X",
    ],
    "F": [
        "FFFFFF",
        "X     ",
        "X     ",
        "XXXXX ",
        "X     ",
        "X     ",
    ],
    "A": [
        "  XXX  ",
        " X   X ",
        "X     X",
        "XXXXXXX",
        "X     X",
        "X     X",
    ],
}


def build_mfa_banner_rows(gap: str = "  ") -> list[str]:
    """Render the 'MFA' banner where each glyph is built from its own letter."""
    letters = ["M", "F", "A"]
    rendered: dict[str, list[str]] = {}
    for letter in letters:
        rendered[letter] = [row.replace("X", letter) for row in _MFA_GLYPHS[letter]]
    height = len(_MFA_GLYPHS["M"])
    rows = []
    for line_index in range(height):
        rows.append(gap.join(rendered[letter][line_index] for letter in letters))
    width = max(len(row) for row in rows)
    return [row.ljust(width) for row in rows]


def play_intro_animation(enabled: bool = True) -> None:
    """Play a short ANSI intro for the splash screen.

    Skipped automatically when disabled or when stdout is not a TTY, so it never
    interferes with piped/redirected output or automation.
    """
    if not enabled or not sys.stdout.isatty():
        return

    reset = "\033[0m"
    cyan = "\033[96m"
    magenta = "\033[95m"
    green = "\033[92m"
    title = "Salesforce MFA Audit"

    term_cols = shutil.get_terminal_size(fallback=(80, 24)).columns

    # Framed Salesforce cloud logo.
    inner = render_salesforce_logo_lines()
    card_width = max(len(r) for r in _SALESFORCE_CLOUD) + _CLOUD_PAD * 2
    logo_border = "+" + "-" * card_width + "+"
    logo = [logo_border] + [f"|{line}|" for line in inner] + [logo_border]
    logo_width = card_width + 2

    # MFA banner.
    mfa = build_mfa_banner_rows()
    mfa_width = max(len(r) for r in mfa)

    gap = "   "
    side_width = logo_width + len(gap) + mfa_width

    # Pick the widest layout that fits the terminal so lines never wrap (wrapping
    # would desync the cursor-up math used for the shimmer and look janky).
    if term_cols >= side_width:
        block_height = max(len(logo), len(mfa))
        logo_top = (block_height - len(logo)) // 2
        mfa_top = (block_height - len(mfa)) // 2

        def compose(color: str) -> list[str]:
            rows = []
            for i in range(block_height):
                li = i - logo_top
                left_segment = logo[li] if 0 <= li < len(logo) else " " * logo_width
                mi = i - mfa_top
                if 0 <= mi < len(mfa):
                    right_segment = f"{color}{mfa[mi]}{reset}"
                else:
                    right_segment = " " * mfa_width
                rows.append(f"{left_segment}{gap}{right_segment}")
            return rows

        total_width = side_width
    elif term_cols >= logo_width:
        # Stack the cloud above the MFA banner, both centered to the cloud width.
        def compose(color: str) -> list[str]:
            rows = list(logo)
            rows.append(" " * logo_width)
            for row in mfa:
                pad = (logo_width - mfa_width) // 2
                rows.append(
                    " " * pad + f"{color}{row}{reset}" + " " * (logo_width - mfa_width - pad)
                )
            return rows

        total_width = logo_width
    elif term_cols >= mfa_width:
        def compose(color: str) -> list[str]:
            return [f"{color}{row}{reset}" for row in mfa]

        total_width = mfa_width
    else:
        # Too narrow for any art: show a compact, wrap-safe text intro.
        try:
            sys.stdout.write(f"\n{cyan}{title[:term_cols]}{reset}\n\n")
            sys.stdout.flush()
        except (OSError, ValueError):
            pass
        return

    height = len(compose(cyan))

    try:
        sys.stdout.write("\n")
        # Reveal line by line.
        for row in compose(cyan):
            sys.stdout.write(row + "\n")
            sys.stdout.flush()
            time.sleep(0.07)
        # Brief color shimmer (safe: the chosen layout fits without wrapping).
        for color in (magenta, green, cyan):
            sys.stdout.write(f"\033[{height}A")
            sys.stdout.write("\n".join(compose(color)) + "\n")
            sys.stdout.flush()
            time.sleep(0.12)
        subtitle = title.center(total_width) if len(title) <= total_width else title[:total_width]
        sys.stdout.write(f"{green}{subtitle}{reset}\n\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        # Never let an animation hiccup block the audit.
        sys.stdout.write("\n")


def build_startup_screen(args: argparse.Namespace) -> str:
    mode_label = (
        f"Sampled large-org mode enabled (`--large-org-sample`): analyzes the first {USER_QUERY_LIMIT} queried users and displays up to {USER_RENDER_LIMIT} user rows."
        if args.large_org_sample
        else "Full mode enabled: runs the fuller analysis path for user counts and risk detection."
    )
    output_targets = []
    if args.output:
        output_targets.append(f"JSON report: {args.output}")
    if args.no_markdown:
        output_targets.append("Markdown report: suppressed (--no-markdown)")
    else:
        markdown_name = args.markdown_file or default_report_filename(args.org)
        output_targets.append(
            f"Markdown report: {markdown_name} (default; use --no-markdown to suppress)"
        )
    if args.html_file:
        output_targets.append(f"HTML report: {args.html_file}")
    elif not args.no_markdown:
        markdown_name = args.markdown_file or default_report_filename(args.org)
        html_name = Path(markdown_name).with_suffix(".html").name
        output_targets.append(f"HTML report: {html_name} (generated alongside the Markdown report)")

    content_lines = [
        "Salesforce MFA Audit Startup",
        "",
        "Disclaimer",
        "   - Some sections rely on sampled login history, available API fields, or",
        "     optional large-org sampling mode. Manual review may still be required",
        "     for complete compliance validation.",
        "",
        "1. What it does",
        "   - Audits MFA-relevant org settings, privileged users, bypass assignments,",
        "     SSO signal history, and non-SSO verification history for the selected org.",
        "",
        "2. Processing / branching options",
        f"   - {mode_label}",
        "   - `--large-org-sample` is recommended for very large orgs that time out",
        "     under the fuller analysis path.",
        "",
        "3. Output files",
    ]
    for target in output_targets:
        content_lines.append(f"   - {target}")
    content_lines.extend(
        [
            "",
            "4. End-of-run choice",
            "   - If an HTML report is generated, the script will ask whether you want",
            "     to open that HTML file after the audit completes.",
            "",
            f"Target org: {args.org}",
            "",
            "Proceed? Enter Y/Yes to continue, or N/No to exit.",
        ]
    )

    return frame_startup_content(content_lines)


def frame_startup_content(content_lines: list[str]) -> str:
    """Wrap the splash content to the terminal width and draw a fitting frame.

    On very narrow terminals the box border is dropped (and text is simply
    wrapped) so the screen never overflows and wraps into an unreadable mess.
    """
    term_cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    natural_width = max(len(line) for line in content_lines)

    # Too narrow to draw a usable frame: print wrapped text without a border.
    if term_cols < 24:
        wrapped: list[str] = []
        for line in content_lines:
            wrapped.extend(wrap_indented(line, max(1, term_cols)))
        return "\n".join(wrapped)

    inner_width = min(natural_width, term_cols - 4)
    wrapped_lines: list[str] = []
    for line in content_lines:
        wrapped_lines.extend(wrap_indented(line, inner_width))

    width = max((len(line) for line in wrapped_lines), default=0)
    border = "+" + "-" * (width + 2) + "+"
    body = [border]
    for line in wrapped_lines:
        body.append(f"| {line.ljust(width)} |")
    body.append(border)
    return "\n".join(body)


def wrap_indented(line: str, width: int) -> list[str]:
    """Wrap a single content line to ``width``, preserving its leading indent
    (and adding a hanging indent for bullet lines)."""
    if not line:
        return [""]
    if len(line) <= width:
        return [line]
    indent = " " * (len(line) - len(line.lstrip(" ")))
    stripped = line.strip()
    subsequent = indent + ("  " if stripped.startswith("- ") else "")
    pieces = textwrap.wrap(
        stripped,
        width=max(1, width),
        initial_indent=indent,
        subsequent_indent=subsequent,
    )
    return pieces or [""]


def confirm_startup(args: argparse.Namespace) -> bool:
    print(build_startup_screen(args))
    response = input("> ").strip().lower()
    return response in {"y", "yes"}


def default_report_filename(org: str | None) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", org or "org").strip("_") or "org"
    return f"{safe}-mfa-report.md"


def prompt_open_html(html_path: Path) -> None:
    print(f"Open HTML report now? `{html_path}`")
    response = input("> ").strip().lower()
    if response not in {"y", "yes"}:
        return
    subprocess.run(["open", str(html_path)], check=False)


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent

    play_intro_animation(enabled=not args.no_intro and not args.json)

    if not check_salesforce_cli():
        return 1

    target_org = resolve_target_org(args)
    if not target_org:
        print("Exiting without running audit.")
        return 1
    args.org = target_org

    if not confirm_startup(args):
        print("Exiting without running audit.")
        return 0

    try:
        report = build_report(args.org, repo_root, large_org_sample=args.large_org_sample)
    except (SfCommandError, ValueError, OSError, ET.ParseError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    latest_html_path: Path | None = None
    scatterplot_svg_path: Path | None = None

    if args.output:
        progress(f"Writing JSON report to {args.output}")
        output_path = Path(args.output)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Markdown is generated by default; --no-markdown suppresses it and
    # --markdown-file overrides the default file name.
    if args.no_markdown:
        markdown_target = None
    elif args.markdown_file:
        markdown_target = Path(args.markdown_file)
    else:
        markdown_target = Path(default_report_filename(args.org))

    if markdown_target is not None:
        progress(f"Writing Markdown report to {markdown_target}")
        scatterplot_svg_path, scatterplot_png_path = write_scatterplot_assets(report, markdown_target)
        relative_scatterplot_path = (
            scatterplot_png_path.name if scatterplot_png_path is not None else scatterplot_svg_path.name
        )
        markdown_target.write_text(
            render_markdown_report(report, scatterplot_image_path=relative_scatterplot_path),
            encoding="utf-8",
        )
        # HTML is generated alongside Markdown by default (unless an explicit
        # --html-file was requested, which is handled separately below).
        if not args.html_file:
            html_path = markdown_target.with_suffix(".html")
            latest_html_path = html_path
            progress(f"Writing HTML report to {html_path}")
            html_path.write_text(
                render_html_report(
                    report, scatterplot_svg=scatterplot_svg_path.read_text(encoding="utf-8")
                ),
                encoding="utf-8",
            )

    if args.html_file:
        progress(f"Writing HTML report to {args.html_file}")
        html_path = Path(args.html_file)
        latest_html_path = html_path
        if scatterplot_svg_path is not None:
            scatterplot_svg = scatterplot_svg_path.read_text(encoding="utf-8")
        else:
            scatterplot_svg = render_issue_scatterplot_svg(build_issue_scatterplot_points(report))
        html_path.write_text(
            render_html_report(report, scatterplot_svg=scatterplot_svg),
            encoding="utf-8",
        )

    if args.json:
        progress("Printing JSON report")
        print(json.dumps(report, indent=2))
    else:
        progress("Printing human-readable report")
        emit_human_report(report)

    if latest_html_path is not None:
        prompt_open_html(latest_html_path)

    progress("Audit complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
