#!/usr/bin/env python3
"""Generate the Salesforce MFA "signal source" analysis in Markdown + HTML.

Single source of truth for the analysis grid so the Markdown (which imports
cleanly into Google Docs) and the styled HTML never drift apart.

Usage:
    python3 generate_signals_analysis.py
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

DOC_TITLE = "Salesforce MFA Audit — Signal Source Analysis"

INTRO = [
    "This document inventories every signal the MFA auditor collects, the source it "
    "is collected from today, the ideal source for that signal, and notes that explain "
    "gaps or fidelity limits. It is organized by collection mechanism.",
    "Use the **Ideal Source** column to prioritize future improvements and the "
    "**Notes** column to understand where a signal may be incomplete or require manual "
    "validation.",
]

LEGEND = [
    ("Phishing-resistant", "FIDO2/WebAuthn, security keys, certificates, built-in authenticator."),
    ("Standard MFA", "TOTP authenticator apps, Salesforce Authenticator, Lightning Login, passkeys."),
    ("Weak / recovery", "SMS, email, temporary codes, password-only — not acceptable as primary MFA."),
]

# Each section: (title, intro, [ (signal, current_source, ideal_source, notes) ])
SECTIONS: list[tuple[str, str, list[tuple[str, str, str, str]]]] = [
    (
        "1. Org-Wide Security Settings",
        "Mechanism: `sf project retrieve start --metadata Settings:Security`, then parse "
        "`Security.settings-meta.xml`. Metadata is authoritative for org configuration.",
        [
            (
                "Direct UI MFA enforcement (org-wide)",
                "Metadata: `Security.settings` → `sessionSettings.enableMFADirectUILoginOptIn`",
                "Same (Metadata API is authoritative)",
                "The canonical switch requiring MFA on direct UI logins. Consider Setup Audit Trail for change history.",
            ),
            (
                "Skip single-factor when direct UI MFA on",
                "Metadata: `sessionSettings.skipSFAWhenMFADirectUILogin`",
                "Same",
                "Interacts with the enforcement toggle; affects whether SFA is bypassed.",
            ),
            (
                "Built-in authenticator available (phishing-resistant)",
                "Metadata: `sessionSettings.enableBuiltInAuthenticator`",
                "Same",
                "Indicates a phishing-resistant method is enabled org-wide.",
            ),
            (
                "Physical security key / U2F / WebAuthn available",
                "Metadata: `sessionSettings.enableU2F`",
                "Same",
                "Enables FIDO/WebAuthn registration (phishing-resistant).",
            ),
            (
                "Lightning Login enabled",
                "Metadata: `sessionSettings.enableLightningLogin`",
                "Same",
                "Passwordless; classified as standard MFA.",
            ),
            (
                "SMS identity enabled",
                "Metadata: `sessionSettings.enableSMSIdentity`",
                "Same",
                "SMS is weak / not phishing-resistant; presence is a risk note.",
            ),
            (
                "SAML SSO enabled",
                "Metadata: `singleSignOnSettings.enableSamlLogin`",
                "Per-config `SamlSsoConfig` + `AuthProvider` metadata (enumerate each path)",
                "Current detection only confirms SAML is on, not per-config behavior.",
            ),
            (
                "Multiple SAML configs",
                "Metadata: `singleSignOnSettings.enableMultipleSamlConfigs`",
                "Same + enumerate each config",
                "Flags that multiple IdP paths exist and each must be validated.",
            ),
            (
                "Salesforce-credentials login disabled",
                "Metadata: `singleSignOnSettings.isLoginWithSalesforceCredentialsDisabled`",
                "Same",
                "If false, native logins remain possible alongside SSO.",
            ),
        ],
    ),
    (
        "2. Privileged Users & MFA-Relevant Permissions",
        "Mechanism: SOQL on `User` (profile permissions) and `PermissionSetAssignment` → "
        "`PermissionSet` permissions.",
        [
            (
                "Privileged: Modify All Data",
                "SOQL: `User.Profile.PermissionsModifyAllData` + `PermissionSet.PermissionsModifyAllData`",
                "Effective/aggregated permissions including Permission Set Groups & muting sets",
                "Current path reads Profile + directly-assigned permission sets; may miss grants via Permission Set Groups or changes from muting permission sets.",
            ),
            (
                "Privileged: View All Data",
                "SOQL: `Profile.PermissionsViewAllData` + `PermissionSet.PermissionsViewAllData`",
                "Effective/aggregated permissions (incl. PSGs)",
                "Same fidelity caveat as above.",
            ),
            (
                "Privileged: Customize Application",
                "SOQL: `Profile.PermissionsCustomizeApplication` + `PermissionSet.PermissionsCustomizeApplication`",
                "Effective/aggregated permissions (incl. PSGs)",
                "Same fidelity caveat as above.",
            ),
            (
                "Privileged: Author Apex",
                "SOQL: `Profile.PermissionsAuthorApex` + `PermissionSet.PermissionsAuthorApex`",
                "Effective/aggregated permissions (incl. PSGs)",
                "Same fidelity caveat as above.",
            ),
            (
                "Per-user UI MFA requirement",
                "SOQL: `Profile.PermissionsForceTwoFactor` + `PermissionSet.PermissionsForceTwoFactor`",
                "Effective/aggregated permissions (incl. PSGs)",
                "“Multi-Factor Authentication for User Interface Logins” permission.",
            ),
            (
                "MFA bypass / waiver",
                "SOQL: `Profile.PermissionsBypassMFAForUiLogins` + `PermissionSet.PermissionsBypassMFAForUiLogins`",
                "Effective/aggregated permissions (incl. PSGs)",
                "“Waive MFA…” permission — high risk; should be enumerated including PSG-derived grants.",
            ),
            (
                "Internal vs external user scoping",
                "SOQL: `User.UserType`, `IsActive`, `IsPortalEnabled`, `Profile.UserLicense.Name`",
                "Same",
                "Heuristic filters; large-org sampling (cap 250 queried / 50 rendered) reduces fidelity.",
            ),
            (
                "Profile context",
                "SOQL: `User.Profile.Name`",
                "Same",
                "Used for display/context (e.g., System Administrator).",
            ),
        ],
    ),
    (
        "3. Registered MFA Methods per User",
        "Mechanism: REST SOQL on `TwoFactorMethodsInfo`, gated by the querying user's "
        "`PermissionsManageTwoFactor` (Manage MFA in API).",
        [
            (
                "Has built-in authenticator",
                "REST: `TwoFactorMethodsInfo.HasBuiltInAuthenticator`",
                "Same (canonical); run as an admin holding Manage MFA in API",
                "Only available when the running user has the permission; otherwise unknown.",
            ),
            (
                "Has Salesforce Authenticator",
                "REST: `TwoFactorMethodsInfo.HasSalesforceAuthenticator`",
                "Same",
                "Standard MFA.",
            ),
            (
                "Has TOTP",
                "REST: `TwoFactorMethodsInfo.HasTotp`",
                "Same",
                "Standard MFA.",
            ),
            (
                "Has U2F",
                "REST: `TwoFactorMethodsInfo.HasU2F`",
                "Same",
                "Phishing-resistant.",
            ),
            (
                "Has security key (WebAuthn)",
                "REST: `TwoFactorMethodsInfo.HasSecurityKey`",
                "Same",
                "Phishing-resistant.",
            ),
            (
                "Verified email / mobile / temp code",
                "REST: `HasUserVerifiedEmailAddress`, `HasUserVerifiedMobileNumber`, `HasVerifiedMobileNumber`, `HasTempCode`",
                "Same",
                "Recovery / weak factors; not acceptable as primary MFA.",
            ),
            (
                "User has registered a COMPLIANT (phishing-resistant) method",
                "Derived from the fields above when accessible",
                "TwoFactorMethodsInfo as admin, or MFA registration / Identity Verification reports",
                "Key gap: when Manage MFA in API is absent, per-user registration status is unknown.",
            ),
        ],
    ),
    (
        "4. SSO Login Signals (AMR / ACR)",
        "Mechanism: SOQL `LoginHistory` (most recent 100 rows). AMR codes are classified "
        "phishing-resistant / standard / weak / unrecognized.",
        [
            (
                "Login is SSO",
                "SOQL: `LoginHistory.AuthenticationServiceId`",
                "Same",
                "Non-null ⇒ SSO via an Auth Provider / SAML config.",
            ),
            (
                "AMR (authentication method reference)",
                "SOQL: `LoginHistory.AuthMethodReference`",
                "IdP assertion + LoginHistory; Event Monitoring `LoginEvent` / Real-Time Events for full coverage",
                "Only populated if the IdP returns AMR. Classified by the auditor's AMR code sets.",
            ),
            (
                "ACR (authn context class reference)",
                "SOQL: first available of `AcrContextClassReference` / `AuthnContextClassRef` / `AcrReference` / `Acr`",
                "IdP SAML `AuthnContextClassRef` from the assertion / IdP logs",
                "Field frequently not exposed in LoginHistory; validate at the IdP.",
            ),
            (
                "Login context (type / app / status / time)",
                "SOQL: `LoginType`, `Application`, `Status`, `LoginTime`",
                "Same",
                "Context only.",
            ),
            (
                "Coverage / completeness",
                "Most-recent 100-row sample",
                "Event Monitoring login event log files / Real-Time Event Monitoring",
                "100 rows are not exhaustive across users or time.",
            ),
        ],
    ),
    (
        "5. Non-SSO Verification Methods",
        "Mechanism: SOQL `VerificationHistory` (most recent 100 rows), joined to "
        "`LoginHistory` to exclude SSO logins.",
        [
            (
                "Verification method used",
                "SOQL: `VerificationHistory.VerificationMethod` (Totp, Sms, Email, SalesforceAuthenticator, U2F, WebAuthnRoamingAuthenticator, PwlessPasskey, BuiltInAuthenticator, TempCode, LL, Password, CustomOtpDelivery)",
                "Same object; fuller history via Event Monitoring `IdentityVerificationEvent` / Real-Time Events",
                "Classified phishing-resistant / standard / weak; recent-sample limited.",
            ),
            (
                "Verification status / time",
                "SOQL: `VerificationHistory.Status`, `VerificationTime`",
                "Same",
                "Context.",
            ),
            (
                "SSO exclusion join",
                "SOQL: `VerificationHistory.LoginHistoryId` → `LoginHistory.AuthenticationServiceId`",
                "Same",
                "Distinguishes native MFA challenges from SSO logins.",
            ),
        ],
    ),
    (
        "6. Connection & Capability Discovery",
        "Mechanism: CLI/version checks and REST describe used to establish the connection "
        "and determine which objects/fields are available.",
        [
            (
                "Salesforce CLI version",
                "`sf --version`",
                "Same",
                "Gates on ≥ v2.0.0.",
            ),
            (
                "Org connection (instance URL, access token)",
                "`sf org display --json`",
                "Same",
                "Used for direct REST calls.",
            ),
            (
                "Object / field availability",
                "REST describe (`/sobjects`, field describe)",
                "Same",
                "Determines whether AMR/ACR and TwoFactorMethodsInfo are accessible in the org.",
            ),
        ],
    ),
    (
        "7. Derived / Computed Indicators",
        "These are not collected signals; they are computed from the sources above and "
        "inherit their fidelity limits.",
        [
            (
                "Org readiness score, users uncovered if UI MFA off, failed-check count, scatterplot metrics",
                "Computed from the signals above",
                "—",
                "Interpretation layer; accuracy is bounded by source fidelity and sampling.",
            ),
        ],
    ),
]

RECOMMENDATIONS = [
    "For SSO, validate AMR/ACR at the Identity Provider and consider Event Monitoring "
    "for complete login and verification history rather than the recent 100-row samples.",
    "Run the auditor with an admin identity that holds **Manage MFA in API** so "
    "`TwoFactorMethodsInfo` populates per-user registration status.",
    "Account for **Permission Set Groups** and **muting permission sets** to make "
    "privileged-user and bypass detection exact.",
    "Enumerate every `SamlSsoConfig` and `AuthProvider` instead of relying on the single "
    "`enableSamlLogin` flag.",
    "Avoid large-org sampling when complete user coverage is required (sampling caps at "
    "250 queried / 50 rendered).",
]


def render_markdown() -> str:
    out: list[str] = [f"# {DOC_TITLE}", ""]
    out.append(f"_Generated {datetime.now():%Y-%m-%d %H:%M}_")
    out.append("")
    for paragraph in INTRO:
        out.append(paragraph)
        out.append("")
    out.append("## Classification legend")
    out.append("")
    out.append("| Class | Meaning |")
    out.append("| --- | --- |")
    for name, meaning in LEGEND:
        out.append(f"| {name} | {meaning} |")
    out.append("")
    for title, intro, rows in SECTIONS:
        out.append(f"## {title}")
        out.append("")
        out.append(intro)
        out.append("")
        out.append("| Signal | Current Source | Ideal Source | Notes |")
        out.append("| --- | --- | --- | --- |")
        for signal, current, ideal, notes in rows:
            out.append(f"| {signal} | {current} | {ideal} | {notes} |")
        out.append("")
    out.append("## Recommendations")
    out.append("")
    for rec in RECOMMENDATIONS:
        out.append(f"- {rec}")
    out.append("")
    return "\n".join(out)


def _esc(text: str) -> str:
    return html.escape(text)


def render_html() -> str:
    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"<title>{_esc(DOC_TITLE)}</title>")
    parts.append(
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
        "color:#16325c;margin:0;padding:2.5rem;background:#f4f6f9;line-height:1.5;}"
        ".wrap{max-width:1100px;margin:0 auto;background:#fff;padding:2.5rem;"
        "border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.08);}"
        "h1{color:#032d60;margin-top:0;} h2{color:#0b5cab;margin-top:2rem;}"
        ".meta{color:#5e6c84;font-size:.9rem;}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.92rem;}"
        "th,td{border:1px solid #d8dde6;padding:.55rem .7rem;vertical-align:top;text-align:left;}"
        "th{background:#0176d3;color:#fff;font-weight:600;}"
        "tbody tr:nth-child(even){background:#f3f7fb;}"
        "code{background:#eef1f6;padding:.05rem .3rem;border-radius:4px;font-size:.85em;}"
        "td:first-child{font-weight:600;width:18%;} "
        ".intro{color:#2b3a55;} ul{margin:.5rem 0 0 1.1rem;}"
        "</style></head><body><div class='wrap'>"
    )
    parts.append(f"<h1>{_esc(DOC_TITLE)}</h1>")
    parts.append(f"<p class='meta'>Generated {datetime.now():%Y-%m-%d %H:%M}</p>")
    for paragraph in INTRO:
        parts.append(f"<p class='intro'>{_inline_html(paragraph)}</p>")

    parts.append("<h2>Classification legend</h2>")
    parts.append("<table><thead><tr><th>Class</th><th>Meaning</th></tr></thead><tbody>")
    for name, meaning in LEGEND:
        parts.append(f"<tr><td>{_esc(name)}</td><td>{_esc(meaning)}</td></tr>")
    parts.append("</tbody></table>")

    for title, intro, rows in SECTIONS:
        parts.append(f"<h2>{_esc(title)}</h2>")
        parts.append(f"<p class='intro'>{_inline_html(intro)}</p>")
        parts.append(
            "<table><thead><tr><th>Signal</th><th>Current Source</th>"
            "<th>Ideal Source</th><th>Notes</th></tr></thead><tbody>"
        )
        for signal, current, ideal, notes in rows:
            parts.append(
                "<tr>"
                f"<td>{_inline_html(signal)}</td>"
                f"<td>{_inline_html(current)}</td>"
                f"<td>{_inline_html(ideal)}</td>"
                f"<td>{_inline_html(notes)}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    parts.append("<h2>Recommendations</h2><ul>")
    for rec in RECOMMENDATIONS:
        parts.append(f"<li>{_inline_html(rec)}</li>")
    parts.append("</ul>")
    parts.append("</div></body></html>")
    return "".join(parts)


def _inline_html(text: str) -> str:
    """Escape, then render simple Markdown inline (`code` and **bold**)."""
    escaped = _esc(text)
    # `code`
    out = []
    in_code = False
    for chunk in escaped.split("`"):
        out.append(f"<code>{chunk}</code>" if in_code else chunk)
        in_code = not in_code
    rendered = "".join(out)
    # **bold**
    bold = []
    in_bold = False
    for chunk in rendered.split("**"):
        bold.append(f"<strong>{chunk}</strong>" if in_bold else chunk)
        in_bold = not in_bold
    return "".join(bold)


def main() -> None:
    base = Path(__file__).resolve().parent
    md_path = base / "mfa-signal-source-analysis.md"
    html_path = base / "mfa-signal-source-analysis.html"
    md_path.write_text(render_markdown(), encoding="utf-8")
    html_path.write_text(render_html(), encoding="utf-8")
    print(f"Wrote {md_path}")
    print(f"Wrote {html_path}")


if __name__ == "__main__":
    main()
