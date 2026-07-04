# Salesforce MFA Audit — Signal Source Analysis

_Generated 2026-06-29 08:33_

This document inventories every signal the MFA auditor collects, the source it is collected from today, the ideal source for that signal, and notes that explain gaps or fidelity limits. It is organized by collection mechanism.

Use the **Ideal Source** column to prioritize future improvements and the **Notes** column to understand where a signal may be incomplete or require manual validation.

## Classification legend

| Class | Meaning |
| --- | --- |
| Phishing-resistant | FIDO2/WebAuthn, security keys, certificates, built-in authenticator. |
| Standard MFA | TOTP authenticator apps, Salesforce Authenticator, Lightning Login, passkeys. |
| Weak / recovery | SMS, email, temporary codes, password-only — not acceptable as primary MFA. |

## 1. Org-Wide Security Settings

Mechanism: `sf project retrieve start --metadata Settings:Security`, then parse `Security.settings-meta.xml`. Metadata is authoritative for org configuration.

| Signal | Current Source | Ideal Source | Notes |
| --- | --- | --- | --- |
| Direct UI MFA enforcement (org-wide) | Metadata: `Security.settings` → `sessionSettings.enableMFADirectUILoginOptIn` | Same (Metadata API is authoritative) | The canonical switch requiring MFA on direct UI logins. Consider Setup Audit Trail for change history. |
| Skip single-factor when direct UI MFA on | Metadata: `sessionSettings.skipSFAWhenMFADirectUILogin` | Same | Interacts with the enforcement toggle; affects whether SFA is bypassed. |
| Built-in authenticator available (phishing-resistant) | Metadata: `sessionSettings.enableBuiltInAuthenticator` | Same | Indicates a phishing-resistant method is enabled org-wide. |
| Physical security key / U2F / WebAuthn available | Metadata: `sessionSettings.enableU2F` | Same | Enables FIDO/WebAuthn registration (phishing-resistant). |
| Lightning Login enabled | Metadata: `sessionSettings.enableLightningLogin` | Same | Passwordless; classified as standard MFA. |
| SMS identity enabled | Metadata: `sessionSettings.enableSMSIdentity` | Same | SMS is weak / not phishing-resistant; presence is a risk note. |
| SAML SSO enabled | Metadata: `singleSignOnSettings.enableSamlLogin` | Per-config `SamlSsoConfig` + `AuthProvider` metadata (enumerate each path) | Current detection only confirms SAML is on, not per-config behavior. |
| Multiple SAML configs | Metadata: `singleSignOnSettings.enableMultipleSamlConfigs` | Same + enumerate each config | Flags that multiple IdP paths exist and each must be validated. |
| Salesforce-credentials login disabled | Metadata: `singleSignOnSettings.isLoginWithSalesforceCredentialsDisabled` | Same | If false, native logins remain possible alongside SSO. |

## 2. Privileged Users & MFA-Relevant Permissions

Mechanism: SOQL on `User` (profile permissions) and `PermissionSetAssignment` → `PermissionSet` permissions.

| Signal | Current Source | Ideal Source | Notes |
| --- | --- | --- | --- |
| Privileged: Modify All Data | SOQL: `User.Profile.PermissionsModifyAllData` + `PermissionSet.PermissionsModifyAllData` | Effective/aggregated permissions including Permission Set Groups & muting sets | Current path reads Profile + directly-assigned permission sets; may miss grants via Permission Set Groups or changes from muting permission sets. |
| Privileged: View All Data | SOQL: `Profile.PermissionsViewAllData` + `PermissionSet.PermissionsViewAllData` | Effective/aggregated permissions (incl. PSGs) | Same fidelity caveat as above. |
| Privileged: Customize Application | SOQL: `Profile.PermissionsCustomizeApplication` + `PermissionSet.PermissionsCustomizeApplication` | Effective/aggregated permissions (incl. PSGs) | Same fidelity caveat as above. |
| Privileged: Author Apex | SOQL: `Profile.PermissionsAuthorApex` + `PermissionSet.PermissionsAuthorApex` | Effective/aggregated permissions (incl. PSGs) | Same fidelity caveat as above. |
| Per-user UI MFA requirement | SOQL: `Profile.PermissionsForceTwoFactor` + `PermissionSet.PermissionsForceTwoFactor` | Effective/aggregated permissions (incl. PSGs) | “Multi-Factor Authentication for User Interface Logins” permission. |
| MFA bypass / waiver | SOQL: `Profile.PermissionsBypassMFAForUiLogins` + `PermissionSet.PermissionsBypassMFAForUiLogins` | Effective/aggregated permissions (incl. PSGs) | “Waive MFA…” permission — high risk; should be enumerated including PSG-derived grants. |
| Internal vs external user scoping | SOQL: `User.UserType`, `IsActive`, `IsPortalEnabled`, `Profile.UserLicense.Name` | Same | Heuristic filters; large-org sampling (cap 250 queried / 50 rendered) reduces fidelity. |
| Profile context | SOQL: `User.Profile.Name` | Same | Used for display/context (e.g., System Administrator). |

## 3. Registered MFA Methods per User

Mechanism: REST SOQL on `TwoFactorMethodsInfo`, gated by the querying user's `PermissionsManageTwoFactor` (Manage MFA in API).

| Signal | Current Source | Ideal Source | Notes |
| --- | --- | --- | --- |
| Has built-in authenticator | REST: `TwoFactorMethodsInfo.HasBuiltInAuthenticator` | Same (canonical); run as an admin holding Manage MFA in API | Only available when the running user has the permission; otherwise unknown. |
| Has Salesforce Authenticator | REST: `TwoFactorMethodsInfo.HasSalesforceAuthenticator` | Same | Standard MFA. |
| Has TOTP | REST: `TwoFactorMethodsInfo.HasTotp` | Same | Standard MFA. |
| Has U2F | REST: `TwoFactorMethodsInfo.HasU2F` | Same | Phishing-resistant. |
| Has security key (WebAuthn) | REST: `TwoFactorMethodsInfo.HasSecurityKey` | Same | Phishing-resistant. |
| Verified email / mobile / temp code | REST: `HasUserVerifiedEmailAddress`, `HasUserVerifiedMobileNumber`, `HasVerifiedMobileNumber`, `HasTempCode` | Same | Recovery / weak factors; not acceptable as primary MFA. |
| User has registered a COMPLIANT (phishing-resistant) method | Derived from the fields above when accessible | TwoFactorMethodsInfo as admin, or MFA registration / Identity Verification reports | Key gap: when Manage MFA in API is absent, per-user registration status is unknown. |

## 4. SSO Login Signals (AMR / ACR)

Mechanism: SOQL `LoginHistory` (most recent 100 rows). AMR codes are classified phishing-resistant / standard / weak / unrecognized.

| Signal | Current Source | Ideal Source | Notes |
| --- | --- | --- | --- |
| Login is SSO | SOQL: `LoginHistory.AuthenticationServiceId` | Same | Non-null ⇒ SSO via an Auth Provider / SAML config. |
| AMR (authentication method reference) | SOQL: `LoginHistory.AuthMethodReference` | IdP assertion + LoginHistory; Event Monitoring `LoginEvent` / Real-Time Events for full coverage | Only populated if the IdP returns AMR. Classified by the auditor's AMR code sets. |
| ACR (authn context class reference) | SOQL: first available of `AcrContextClassReference` / `AuthnContextClassRef` / `AcrReference` / `Acr` | IdP SAML `AuthnContextClassRef` from the assertion / IdP logs | Field frequently not exposed in LoginHistory; validate at the IdP. |
| Login context (type / app / status / time) | SOQL: `LoginType`, `Application`, `Status`, `LoginTime` | Same | Context only. |
| Coverage / completeness | Most-recent 100-row sample | Event Monitoring login event log files / Real-Time Event Monitoring | 100 rows are not exhaustive across users or time. |

## 5. Non-SSO Verification Methods

Mechanism: SOQL `VerificationHistory` (most recent 100 rows), joined to `LoginHistory` to exclude SSO logins.

| Signal | Current Source | Ideal Source | Notes |
| --- | --- | --- | --- |
| Verification method used | SOQL: `VerificationHistory.VerificationMethod` (Totp, Sms, Email, SalesforceAuthenticator, U2F, WebAuthnRoamingAuthenticator, PwlessPasskey, BuiltInAuthenticator, TempCode, LL, Password, CustomOtpDelivery) | Same object; fuller history via Event Monitoring `IdentityVerificationEvent` / Real-Time Events | Classified phishing-resistant / standard / weak; recent-sample limited. |
| Verification status / time | SOQL: `VerificationHistory.Status`, `VerificationTime` | Same | Context. |
| SSO exclusion join | SOQL: `VerificationHistory.LoginHistoryId` → `LoginHistory.AuthenticationServiceId` | Same | Distinguishes native MFA challenges from SSO logins. |

## 6. Connection & Capability Discovery

Mechanism: CLI/version checks and REST describe used to establish the connection and determine which objects/fields are available.

| Signal | Current Source | Ideal Source | Notes |
| --- | --- | --- | --- |
| Salesforce CLI version | `sf --version` | Same | Gates on ≥ v2.0.0. |
| Org connection (instance URL, access token) | `sf org display --json` | Same | Used for direct REST calls. |
| Object / field availability | REST describe (`/sobjects`, field describe) | Same | Determines whether AMR/ACR and TwoFactorMethodsInfo are accessible in the org. |

## 7. Derived / Computed Indicators

These are not collected signals; they are computed from the sources above and inherit their fidelity limits.

| Signal | Current Source | Ideal Source | Notes |
| --- | --- | --- | --- |
| Org readiness score, users uncovered if UI MFA off, failed-check count, scatterplot metrics | Computed from the signals above | — | Interpretation layer; accuracy is bounded by source fidelity and sampling. |

## Recommendations

- For SSO, validate AMR/ACR at the Identity Provider and consider Event Monitoring for complete login and verification history rather than the recent 100-row samples.
- Run the auditor with an admin identity that holds **Manage MFA in API** so `TwoFactorMethodsInfo` populates per-user registration status.
- Account for **Permission Set Groups** and **muting permission sets** to make privileged-user and bypass detection exact.
- Enumerate every `SamlSsoConfig` and `AuthProvider` instead of relying on the single `enableSamlLogin` flag.
- Avoid large-org sampling when complete user coverage is required (sampling caps at 250 queried / 50 rendered).
