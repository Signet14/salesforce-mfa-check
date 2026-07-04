import json
import shutil
import unittest
from unittest import mock

import audit_mfa


class AuditMfaTests(unittest.TestCase):
    def test_extract_json_payload_ignores_cli_warning_lines(self) -> None:
        output = """ ›   Warning: update available\n{\n  "status": 0,\n  "result": {"ok": true}\n}\n"""
        payload = audit_mfa.extract_json_payload(output)
        self.assertEqual(payload["result"]["ok"], True)

    def test_parse_security_settings_reads_mfa_flags(self) -> None:
        xml_text = """<?xml version="1.0" encoding="UTF-8"?>
<SecuritySettings xmlns="http://soap.sforce.com/2006/04/metadata">
    <sessionSettings>
        <enableBuiltInAuthenticator>true</enableBuiltInAuthenticator>
        <enableU2F>false</enableU2F>
        <enableMFADirectUILoginOptIn>true</enableMFADirectUILoginOptIn>
        <skipSFAWhenMFADirectUILogin>false</skipSFAWhenMFADirectUILogin>
        <enableLightningLogin>true</enableLightningLogin>
        <enableSMSIdentity>true</enableSMSIdentity>
    </sessionSettings>
    <singleSignOnSettings>
        <enableSamlLogin>true</enableSamlLogin>
        <enableMultipleSamlConfigs>false</enableMultipleSamlConfigs>
        <isLoginWithSalesforceCredentialsDisabled>true</isLoginWithSalesforceCredentialsDisabled>
    </singleSignOnSettings>
</SecuritySettings>
"""
        parsed = audit_mfa.parse_security_settings(xml_text)
        self.assertTrue(parsed["sessionSettings"]["enableBuiltInAuthenticator"])
        self.assertFalse(parsed["sessionSettings"]["enableU2F"])
        self.assertTrue(parsed["sessionSettings"]["enableMFADirectUILoginOptIn"])
        self.assertTrue(parsed["singleSignOnSettings"]["enableSamlLogin"])
        self.assertTrue(parsed["singleSignOnSettings"]["isLoginWithSalesforceCredentialsDisabled"])

    def test_is_internal_user_filters_external_and_automated_users(self) -> None:
        internal = {
            "UserType": "Standard",
            "IsPortalEnabled": False,
            "Profile": {"UserLicense": {"Name": "Salesforce"}},
        }
        guest = {
            "UserType": "Guest",
            "IsPortalEnabled": False,
            "Profile": {"UserLicense": {"Name": "Guest"}},
        }
        automated = {
            "UserType": "AutomatedProcess",
            "IsPortalEnabled": False,
            "Profile": None,
        }

        self.assertTrue(audit_mfa.is_internal_user(internal))
        self.assertFalse(audit_mfa.is_internal_user(guest))
        self.assertFalse(audit_mfa.is_internal_user(automated))

    def test_collect_privileged_reasons_merges_profile_and_permission_set(self) -> None:
        user = {
            "Profile": {
                "Name": "Custom Admin",
                "PermissionsModifyAllData": True,
                "PermissionsViewAllData": False,
                "PermissionsCustomizeApplication": False,
                "PermissionsAuthorApex": False,
            }
        }
        assignment_rows = [
            {
                "PermissionSet": {
                    "Label": "Admin Extras",
                    "PermissionsModifyAllData": False,
                    "PermissionsViewAllData": False,
                    "PermissionsCustomizeApplication": True,
                    "PermissionsAuthorApex": True,
                }
            }
        ]
        reasons = audit_mfa.collect_privileged_reasons(user, assignment_rows)
        self.assertIn("Profile permission: Modify All Data", reasons)
        self.assertIn(
            "Permission set 'Admin Extras': Customize Application, Author Apex",
            reasons,
        )

    def test_count_failed_security_checks_uses_security_only_ids(self) -> None:
        report = {
            "checks": [
                {"id": "direct_ui_mfa_enabled", "status": "FAIL"},
                {"id": "built_in_authenticator_enabled", "status": "FAIL"},
                {"id": "security_key_enabled", "status": "FAIL"},
                {"id": "privileged_user_method_readiness", "status": "FAIL"},
                {"id": "bypass_assignments", "status": "FAIL"},
                {"id": "sso_signal_validation", "status": "WARN"},
            ]
        }
        self.assertEqual(audit_mfa.count_failed_security_checks(report), 4)

    def test_scatterplot_includes_logins_without_acceptable_signal(self) -> None:
        report = {
            "settings": {
                "sessionSettings": {
                    "enableBuiltInAuthenticator": True,
                    "enableU2F": True,
                }
            },
            "summary": {
                "privilegedInternalUserCount": 0,
                "usersWithBypassAssignments": 0,
                "uncoveredInternalUsersIfOrgSwitchOff": 42,
            },
            "checks": [],
            "ssoLoginSignalAnalysis": {
                "sampleSize": 100,
                "missingSignalCount": 3,
                "weakOrNoMfaMatchCount": 2,
                "unrecognizedSignalCount": 1,
            },
        }
        points = audit_mfa.build_issue_scatterplot_points(report)
        signal_point = next(
            point
            for point in points
            if point["label"] == "Logins without acceptable MFA signal"
        )
        self.assertEqual(signal_point["count"], 6)
        self.assertIn("100 sampled logins", signal_point["description"])

        uncovered_point = next(
            point
            for point in points
            if point["label"] == "Users uncovered if UI MFA off"
        )
        self.assertEqual(uncovered_point["count"], 42)

    def test_classify_signal_codes_prefers_phishing_resistant(self) -> None:
        classified = audit_mfa.classify_signal_codes(["pwd", "multipleauthn", "fido2"])
        self.assertEqual(classified["status"], "PASS")
        self.assertEqual(classified["label"], "Phishing-resistant MFA")
        self.assertIn("fido2", classified["matchedCodes"])

    def test_classify_verification_method_supports_passkey(self) -> None:
        status, label = audit_mfa.classify_verification_method("PwlessPasskey")
        self.assertEqual(status, "PASS")
        self.assertEqual(label, "Phishing-resistant MFA")

    def test_query_all_records_rest_follows_next_records_url(self) -> None:
        org_info = {
            "instanceUrl": "https://example.my.salesforce.com",
            "accessToken": "token",
        }
        responses = [
            {
                "records": [{"Id": "1"}],
                "nextRecordsUrl": "/services/data/v66.0/query/01g-next",
            },
            {
                "records": [{"Id": "2"}],
                "done": True,
            },
        ]
        with mock.patch("audit_mfa.curl_json", side_effect=responses) as mocked_curl:
            records = audit_mfa.query_all_records_rest(org_info, "SELECT Id FROM User")

        self.assertEqual(records, [{"Id": "1"}, {"Id": "2"}])
        self.assertEqual(mocked_curl.call_count, 2)

    def test_check_salesforce_cli_present(self) -> None:
        with mock.patch("audit_mfa.shutil.which", return_value="/usr/local/bin/sf"), mock.patch(
            "audit_mfa.get_salesforce_cli_version",
            return_value="@salesforce/cli/2.128.5 darwin-arm64 node-v22.22.1",
        ):
            self.assertTrue(audit_mfa.check_salesforce_cli())

    def test_check_salesforce_cli_missing(self) -> None:
        with mock.patch("audit_mfa.shutil.which", return_value=None):
            self.assertFalse(audit_mfa.check_salesforce_cli())

    def test_check_salesforce_cli_below_min_warns_but_passes(self) -> None:
        with mock.patch("audit_mfa.shutil.which", return_value="/usr/local/bin/sf"), mock.patch(
            "audit_mfa.get_salesforce_cli_version", return_value="sfdx-cli/1.95.0 linux-x64"
        ):
            self.assertTrue(audit_mfa.check_salesforce_cli())

    def test_parse_cli_version_reads_salesforce_format(self) -> None:
        self.assertEqual(
            audit_mfa.parse_cli_version("@salesforce/cli/2.128.5 darwin-arm64 node-v22.22.1"),
            (2, 128, 5),
        )

    def test_parse_cli_version_handles_unparseable(self) -> None:
        self.assertIsNone(audit_mfa.parse_cli_version("no version here"))
        self.assertIsNone(audit_mfa.parse_cli_version(None))

    def test_collect_orgs_dedupes_across_buckets(self) -> None:
        payload = {
            "result": {
                "nonScratchOrgs": [
                    {
                        "alias": "MyOrg",
                        "username": "rick@example.com",
                        "orgId": "00D1",
                        "isDefaultUsername": True,
                        "isSandbox": False,
                        "connectedStatus": "Connected",
                    },
                    {
                        "alias": "Sbx",
                        "username": "rick@example.com.sandbox",
                        "orgId": "00D2",
                        "isSandbox": True,
                    },
                ],
                "devHubs": [
                    {
                        "alias": "MyOrg",
                        "username": "rick@example.com",
                        "orgId": "00D1",
                        "isDevHub": True,
                    }
                ],
                "other": [],
                "scratchOrgs": [],
                "sandboxes": [],
            }
        }
        orgs = audit_mfa.collect_orgs_from_list_payload(payload)
        self.assertEqual(len(orgs), 2)
        # Default org sorts first and merges the dev-hub flag from the other bucket.
        self.assertEqual(orgs[0]["username"], "rick@example.com")
        self.assertTrue(orgs[0]["isDevHub"])
        self.assertTrue(orgs[0]["isDefaultUsername"])

    def test_describe_org_type_and_identifier(self) -> None:
        self.assertEqual(
            audit_mfa.describe_org_type({"isSandbox": True}), "sandbox"
        )
        self.assertEqual(
            audit_mfa.describe_org_type({"isDevHub": True}), "production / dev hub"
        )
        self.assertEqual(
            audit_mfa.org_identifier({"alias": "A", "username": "u@x"}), "A"
        )
        self.assertEqual(
            audit_mfa.org_identifier({"alias": "", "username": "u@x"}), "u@x"
        )

    def test_mfa_banner_uses_own_letters(self) -> None:
        rows = audit_mfa.build_mfa_banner_rows()
        joined = "\n".join(rows)
        # Each glyph is composed of its own character; no template "X" leaks.
        self.assertNotIn("X", joined)
        self.assertIn("M", joined)
        self.assertIn("F", joined)
        self.assertIn("A", joined)
        # All rows are padded to a uniform width.
        self.assertEqual(len({len(row) for row in rows}), 1)

    @staticmethod
    def _startup_args() -> object:
        import types

        return types.SimpleNamespace(
            large_org_sample=False,
            output=None,
            no_markdown=False,
            markdown_file=None,
            html_file=None,
            org="MyOrg",
        )

    def test_startup_screen_fits_narrow_terminal(self) -> None:
        args = self._startup_args()
        with mock.patch(
            "audit_mfa.shutil.get_terminal_size",
            return_value=mock.Mock(columns=44, lines=24),
        ):
            screen = audit_mfa.build_startup_screen(args)
        for line in screen.splitlines():
            self.assertLessEqual(len(line), 44, msg=line)
        self.assertIn("Salesforce MFA Audit Startup", screen)

    def test_startup_screen_very_narrow_drops_frame(self) -> None:
        args = self._startup_args()
        with mock.patch(
            "audit_mfa.shutil.get_terminal_size",
            return_value=mock.Mock(columns=18, lines=24),
        ):
            screen = audit_mfa.build_startup_screen(args)
        for line in screen.splitlines():
            self.assertLessEqual(len(line), 18, msg=line)
        # No box border is drawn at this width.
        self.assertNotIn("+--", screen)

    def test_startup_screen_wide_terminal_keeps_box(self) -> None:
        args = self._startup_args()
        with mock.patch(
            "audit_mfa.shutil.get_terminal_size",
            return_value=mock.Mock(columns=120, lines=24),
        ):
            screen = audit_mfa.build_startup_screen(args)
        self.assertTrue(screen.startswith("+--"))
        self.assertIn("Proceed?", screen)

    def test_create_ephemeral_sfdx_project_is_self_contained(self) -> None:
        project_root = audit_mfa.create_ephemeral_sfdx_project()
        try:
            project_file = project_root / "sfdx-project.json"
            self.assertTrue(project_file.is_file())
            self.assertTrue((project_root / "force-app").is_dir())
            data = json.loads(project_file.read_text(encoding="utf-8"))
            self.assertIn("packageDirectories", data)
        finally:
            shutil.rmtree(project_root, ignore_errors=True)

    def test_salesforce_cloud_filled_with_s(self) -> None:
        rows = audit_mfa.build_salesforce_cloud_rows()
        joined = "\n".join(rows)
        self.assertNotIn("X", joined)
        self.assertIn("S", joined)
        self.assertEqual(len({len(row) for row in rows}), 1)

    def test_salesforce_logo_has_wordmark_and_colors(self) -> None:
        lines = audit_mfa.render_salesforce_logo_lines()
        joined = "".join(lines)
        # White "Salesforce" wordmark sits inside the cloud as a contiguous run.
        self.assertIn("Salesforce", joined)
        # Uses blue cloud + white background ANSI codes.
        self.assertIn("48;5;39", joined)
        self.assertIn("48;5;231", joined)

    def test_play_intro_animation_skipped_when_not_tty(self) -> None:
        with mock.patch("audit_mfa.sys.stdout") as fake_stdout:
            fake_stdout.isatty.return_value = False
            audit_mfa.play_intro_animation(enabled=True)
            fake_stdout.write.assert_not_called()

    def test_default_report_filename_sanitizes_org(self) -> None:
        self.assertEqual(audit_mfa.default_report_filename("MyOrg"), "MyOrg-mfa-report.md")
        self.assertEqual(
            audit_mfa.default_report_filename("rick@intellitech.net"),
            "rick_intellitech.net-mfa-report.md",
        )
        self.assertEqual(audit_mfa.default_report_filename(None), "org-mfa-report.md")

    def test_resolve_target_org_returns_passed_org(self) -> None:
        args = mock.Mock(org="MyOrg")
        self.assertEqual(audit_mfa.resolve_target_org(args), "MyOrg")

    def test_resolve_target_org_non_tty_without_org(self) -> None:
        args = mock.Mock(org=None)
        with mock.patch("audit_mfa.sys.stdin") as fake_stdin:
            fake_stdin.isatty.return_value = False
            self.assertIsNone(audit_mfa.resolve_target_org(args))

    def _make_report_with_privileged(self, count: int, sampling_enabled: bool) -> dict:
        users = [
            {
                "id": f"005{i:013d}",
                "name": f"User{i} Last{i}",
                "username": f"user{i}@example.com",
                "userType": "Standard",
                "profile": "System Administrator",
                "privilegeReasons": ["Profile: System Administrator"],
                "bypassMfaAssignments": [],
                "availableMfaMethods": [],
            }
            for i in range(count)
        ]
        empty_sso = {
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
        }
        empty_non_sso = {
            "sampleSize": 0,
            "nonSsoVerificationCount": 0,
            "phishingResistantCount": 0,
            "standardCount": 0,
            "weakOrRecoveryCount": 0,
            "unrecognizedCount": 0,
            "observedMethods": [],
            "verificationRows": [],
        }
        report = {
            "org": {"alias": "MyOrg", "username": "admin@org.test", "instanceUrl": "https://x"},
            "run": {"generatedAt": "2026-06-09 00:00:00 EDT-0400"},
            "summary": {
                "activeInternalUserCount": count,
                "privilegedInternalUserCount": count,
                "usersWithBypassAssignments": 0,
                "usersWithPermissionBasedUiMfa": 0,
                "uncoveredInternalUsersIfOrgSwitchOff": 0,
                "samlConfigCount": 0,
                "usersWithVisibleMfaMethods": 0,
            },
            "settings": {
                "sessionSettings": {
                    "enableMFADirectUILoginOptIn": True,
                    "enableBuiltInAuthenticator": True,
                    "enableU2F": True,
                    "enableLightningLogin": False,
                    "enableSMSIdentity": False,
                },
                "singleSignOnSettings": {
                    "enableSamlLogin": False,
                    "enableMultipleSamlConfigs": False,
                    "isLoginWithSalesforceCredentialsDisabled": False,
                },
            },
            "checks": [],
            "details": {
                "privilegedUsers": users,
                "usersWithBypassAssignments": [],
                "uncoveredInternalUsersIfOrgSwitchOff": [],
                "samlConfigs": [],
                "mfaMethodsAccess": {"available": False, "reason": "x", "grantedBy": []},
                "ssoLoginSignalAnalysis": empty_sso,
                "nonSsoVerificationAnalysis": empty_non_sso,
            },
            "manualReview": [],
        }
        if sampling_enabled:
            report["sampling"] = {"enabled": True, "userQueryLimit": 250, "userRenderLimit": 50}
        return report

    def test_default_mode_renders_all_privileged_users(self) -> None:
        rendered = audit_mfa.render_markdown_report(
            self._make_report_with_privileged(70, sampling_enabled=False)
        )
        self.assertEqual(rendered.count("@example.com"), 70)

    def test_sampled_mode_caps_rendered_privileged_users(self) -> None:
        rendered = audit_mfa.render_markdown_report(
            self._make_report_with_privileged(70, sampling_enabled=True)
        )
        self.assertEqual(rendered.count("@example.com"), 50)

    def test_render_markdown_report_includes_sections_and_icons(self) -> None:
        report = {
            "org": {
                "alias": "MyOrg",
                "username": "user@example.com",
                "instanceUrl": "https://example.my.salesforce.com",
            },
            "run": {
                "generatedAt": "2026-06-08 00:24:00 EDT-0400",
            },
            "sampling": {
                "enabled": True,
                "userQueryLimit": 1000,
                "userRenderLimit": 50,
            },
            "summary": {
                "activeInternalUserCount": 1,
                "privilegedInternalUserCount": 1,
                "usersWithBypassAssignments": 0,
                "usersWithPermissionBasedUiMfa": 0,
                "uncoveredInternalUsersIfOrgSwitchOff": 0,
                "samlConfigCount": 0,
                "usersWithVisibleMfaMethods": 1,
            },
            "settings": {
                "sessionSettings": {
                    "enableMFADirectUILoginOptIn": True,
                    "enableBuiltInAuthenticator": True,
                    "enableU2F": False,
                    "enableLightningLogin": True,
                    "enableSMSIdentity": False,
                },
                "singleSignOnSettings": {
                    "enableSamlLogin": False,
                    "enableMultipleSamlConfigs": False,
                    "isLoginWithSalesforceCredentialsDisabled": False,
                },
            },
            "checks": [
                {"id": "direct_ui_mfa_enabled", "status": "PASS", "message": "Example pass", "value": True},
                {"id": "built_in_authenticator_enabled", "status": "FAIL", "message": "Example fail", "count": 1},
            ],
            "details": {
                "privilegedUsers": [
                    {
                        "name": "Test User",
                        "username": "test@example.com",
                        "privilegeReasons": ["Profile: System Administrator"],
                        "availableMfaMethods": ["OTP app (TOTP)", "Hardware key"],
                    }
                ],
                "usersWithBypassAssignments": [],
                "uncoveredInternalUsersIfOrgSwitchOff": [],
                "mfaMethodsAccess": {
                    "available": True,
                    "reason": None,
                    "grantedBy": ["Profile"],
                },
                "ssoLoginSignalAnalysis": {
                    "sampleSize": 3,
                    "ssoLoginCount": 1,
                    "rowsWithAuthMethodReference": 1,
                    "rowsWithAcrContextReference": 0,
                    "phishingResistantMatchCount": 0,
                    "standardMatchCount": 1,
                    "weakOrNoMfaMatchCount": 0,
                    "unrecognizedSignalCount": 0,
                    "missingSignalCount": 2,
                    "fieldAvailability": {
                        "authMethodReference": True,
                        "acrContextClassReference": False,
                        "acrFieldName": None,
                    },
                    "observedCodes": [
                        {
                            "code": "multipleauthn",
                            "count": 1,
                            "classification": "Standard MFA",
                            "status": "WARN",
                        }
                    ],
                    "signalRows": [
                        {
                            "loginTime": "2026-06-08T00:20:00.000+0000",
                            "userId": "005xx",
                            "userName": "Test User",
                            "username": "test@example.com",
                            "application": "Browser",
                            "authMethodReference": "multipleauthn",
                            "acrContextClassReference": None,
                            "classification": "Standard MFA",
                            "classificationStatus": "WARN",
                        }
                    ],
                },
                "nonSsoVerificationAnalysis": {
                    "sampleSize": 2,
                    "nonSsoVerificationCount": 2,
                    "phishingResistantCount": 0,
                    "standardCount": 1,
                    "weakOrRecoveryCount": 1,
                    "unrecognizedCount": 0,
                    "observedMethods": [
                        {
                            "method": "Totp",
                            "label": "One-time password",
                            "count": 1,
                            "classification": "Standard MFA",
                            "status": "WARN",
                        },
                        {
                            "method": "Email",
                            "label": "Email message",
                            "count": 1,
                            "classification": "Weak / recovery / not phishing-resistant",
                            "status": "FAIL",
                        },
                    ],
                    "verificationRows": [
                        {
                            "verificationTime": "2026-06-08T00:30:00.000+0000",
                            "verificationMethod": "Totp",
                            "verificationMethodLabel": "One-time password",
                            "classification": "Standard MFA",
                            "classificationStatus": "WARN",
                            "userId": "005xx",
                            "userName": "Test User",
                            "username": "test@example.com",
                            "application": "Browser",
                        }
                    ],
                },
            },
            "manualReview": [
                {"topic": "Example review", "reason": "Needs manual check", "requiredWhen": True}
            ],
        }
        rendered = audit_mfa.render_markdown_report(
            report, scatterplot_image_path="mfa-report-scatterplot.png"
        )
        self.assertTrue(rendered.startswith("# Salesforce MFA Audit Report\n_Run at: 2026-06-08 00:24:00 EDT-0400_"))
        self.assertIn("## Executive Summary", rendered)
        self.assertIn("> **Overall readiness:**", rendered)
        self.assertIn("## Issue Scatterplot", rendered)
        self.assertIn("![MyOrg MFA issue scatterplot](mfa-report-scatterplot.png)", rendered)
        self.assertIn("Lack of MFA options", rendered)
        self.assertIn("Failed security checks", rendered)
        self.assertIn("Elevated permissions", rendered)
        self.assertIn("Waive MFA permission instances", rendered)
        self.assertIn("## Configurations", rendered)
        self.assertIn("## SSO Signal History", rendered)
        self.assertIn("`multipleauthn` observed 1 time(s) -> Standard MFA", rendered)
        self.assertIn("Match: Standard MFA", rendered)
        self.assertIn("**Sampling note:** User-based counts and user lists in this report are based on the first 1000 queried users", rendered)
        self.assertIn("## Non-SSO Verification History", rendered)
        self.assertIn("`Totp` (One-time password) observed 1 time(s) -> Standard MFA", rendered)
        self.assertIn("## Users", rendered)
        self.assertIn("> **Section score:**", rendered)
        self.assertIn("✅ **PASS**: Example pass [True]", rendered)
        self.assertIn("❌ **FAIL**: Example fail [1]", rendered)
        self.assertIn("Available MFA methods: OTP app (TOTP), Hardware key", rendered)

    def test_render_html_report_includes_inline_svg(self) -> None:
        report = {
            "org": {
                "alias": "MyOrg",
                "username": "user@example.com",
                "instanceUrl": "https://example.my.salesforce.com",
            },
            "run": {
                "generatedAt": "2026-06-08 00:24:00 EDT-0400",
            },
            "sampling": {
                "enabled": True,
                "userQueryLimit": 1000,
                "userRenderLimit": 50,
            },
            "summary": {
                "activeInternalUserCount": 1,
                "privilegedInternalUserCount": 1,
                "usersWithBypassAssignments": 0,
                "usersWithPermissionBasedUiMfa": 0,
                "uncoveredInternalUsersIfOrgSwitchOff": 0,
                "samlConfigCount": 0,
                "usersWithVisibleMfaMethods": 1,
            },
            "settings": {
                "sessionSettings": {
                    "enableMFADirectUILoginOptIn": True,
                    "enableBuiltInAuthenticator": True,
                    "enableU2F": False,
                    "enableLightningLogin": True,
                    "enableSMSIdentity": False,
                },
                "singleSignOnSettings": {
                    "enableSamlLogin": False,
                    "enableMultipleSamlConfigs": False,
                    "isLoginWithSalesforceCredentialsDisabled": False,
                },
            },
            "checks": [
                {"id": "direct_ui_mfa_enabled", "status": "PASS", "message": "Example pass", "value": True},
                {"id": "built_in_authenticator_enabled", "status": "FAIL", "message": "Example fail", "count": 1},
            ],
            "details": {
                "privilegedUsers": [
                    {
                        "name": "Test User",
                        "username": "test@example.com",
                        "privilegeReasons": ["Profile: System Administrator"],
                        "availableMfaMethods": ["OTP app (TOTP)", "Hardware key"],
                    }
                ],
                "usersWithBypassAssignments": [],
                "uncoveredInternalUsersIfOrgSwitchOff": [],
                "mfaMethodsAccess": {
                    "available": True,
                    "reason": None,
                    "grantedBy": ["Profile"],
                },
                "ssoLoginSignalAnalysis": {
                    "sampleSize": 3,
                    "ssoLoginCount": 1,
                    "rowsWithAuthMethodReference": 1,
                    "rowsWithAcrContextReference": 0,
                    "phishingResistantMatchCount": 0,
                    "standardMatchCount": 1,
                    "weakOrNoMfaMatchCount": 0,
                    "unrecognizedSignalCount": 0,
                    "missingSignalCount": 2,
                    "fieldAvailability": {
                        "authMethodReference": True,
                        "acrContextClassReference": False,
                        "acrFieldName": None,
                    },
                    "observedCodes": [
                        {
                            "code": "multipleauthn",
                            "count": 1,
                            "classification": "Standard MFA",
                            "status": "WARN",
                        }
                    ],
                    "signalRows": [
                        {
                            "loginTime": "2026-06-08T00:20:00.000+0000",
                            "userId": "005xx",
                            "userName": "Test User",
                            "username": "test@example.com",
                            "application": "Browser",
                            "authMethodReference": "multipleauthn",
                            "acrContextClassReference": None,
                            "classification": "Standard MFA",
                            "classificationStatus": "WARN",
                        }
                    ],
                },
                "nonSsoVerificationAnalysis": {
                    "sampleSize": 2,
                    "nonSsoVerificationCount": 2,
                    "phishingResistantCount": 0,
                    "standardCount": 1,
                    "weakOrRecoveryCount": 1,
                    "unrecognizedCount": 0,
                    "observedMethods": [
                        {
                            "method": "Totp",
                            "label": "One-time password",
                            "count": 1,
                            "classification": "Standard MFA",
                            "status": "WARN",
                        }
                    ],
                    "verificationRows": [
                        {
                            "verificationTime": "2026-06-08T00:30:00.000+0000",
                            "verificationMethod": "Totp",
                            "verificationMethodLabel": "One-time password",
                            "classification": "Standard MFA",
                            "classificationStatus": "WARN",
                            "userId": "005xx",
                            "userName": "Test User",
                            "username": "test@example.com",
                            "application": "Browser",
                        }
                    ],
                },
            },
            "manualReview": [
                {"topic": "Example review", "reason": "Needs manual check", "requiredWhen": True}
            ],
        }
        rendered = audit_mfa.render_html_report(report, scatterplot_svg="<svg><circle /></svg>")
        self.assertIn("<!DOCTYPE html>", rendered)
        self.assertIn("<svg><circle /></svg>", rendered)
        self.assertIn("Failed security checks", rendered)
        self.assertIn("SSO Signal History", rendered)
        self.assertIn("Non-SSO Verification History", rendered)
        self.assertIn("multipleauthn", rendered)
        self.assertIn("Totp", rendered)
        self.assertIn("Sampling note", rendered)
        self.assertIn("Salesforce MFA Audit Report", rendered)


if __name__ == "__main__":
    unittest.main()
