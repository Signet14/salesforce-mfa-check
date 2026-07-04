# Salesforce MFA Audit Report

## Executive Summary
> **Overall readiness:** ❌ **Not ready**
> **Section score:** 1/6 passing | ❌ 5 fail

- **Primary takeaway:** 4 privileged internal user(s) must be ready for phishing-resistant MFA, and 1 bypass assignment(s) were detected.
- **Coverage snapshot:** 9 active internal user(s), 0 user(s) with permission-based UI MFA, 9 user(s) not covered if org-wide UI MFA is off.
- **Per-user MFA methods:** unavailable. Current querying user does not have Manage MFA in API (PermissionsManageTwoFactor).
- **SSO snapshot:** 0 SAML config(s) detected.

## Org
- **Alias:** `MyOrg`
- **Username:** `rick@intellitech.net`
- **Instance:** `https://2600-dev-ed.my.salesforce.com`

---

## Issue Scatterplot
> **Section score:** 0/1 passing | ⚠️ 1 warning

Bubble size and Y-axis both reflect the number of occurrences for each MFA issue category.

<svg viewBox="0 0 760 360" width="760" height="360" role="img" aria-label="Scatterplot of MFA issues by category">
<rect x="0" y="0" width="100%" height="100%" fill="white" />
<line x1="90" y1="30" x2="90" y2="250" stroke="#4b5563" stroke-width="1.5" />
<line x1="90" y1="250" x2="730" y2="250" stroke="#4b5563" stroke-width="1.5" />
<line x1="90" y1="250.0" x2="730" y2="250.0" stroke="#e5e7eb" stroke-width="1" />
<text x="78" y="254.0" text-anchor="end" font-size="12" fill="#6b7280">0</text>
<line x1="90" y1="195.0" x2="730" y2="195.0" stroke="#e5e7eb" stroke-width="1" />
<text x="78" y="199.0" text-anchor="end" font-size="12" fill="#6b7280">1</text>
<line x1="90" y1="140.0" x2="730" y2="140.0" stroke="#e5e7eb" stroke-width="1" />
<text x="78" y="144.0" text-anchor="end" font-size="12" fill="#6b7280">2</text>
<line x1="90" y1="85.0" x2="730" y2="85.0" stroke="#e5e7eb" stroke-width="1" />
<text x="78" y="89.0" text-anchor="end" font-size="12" fill="#6b7280">3</text>
<line x1="90" y1="30.0" x2="730" y2="30.0" stroke="#e5e7eb" stroke-width="1" />
<text x="78" y="34.0" text-anchor="end" font-size="12" fill="#6b7280">4</text>
<circle cx="90.0" cy="140.0" r="24" fill="#bfdbfe" stroke="#2563eb" stroke-width="2" fill-opacity="0.9" />
<text x="90.0" y="144.0" text-anchor="middle" font-size="13" font-weight="600" fill="#111827">2</text>
<text x="90.0" y="278" text-anchor="middle" font-size="12" fill="#374151">Lack of MFA options</text>
<circle cx="410.0" cy="30.0" r="36" fill="#bfdbfe" stroke="#2563eb" stroke-width="2" fill-opacity="0.9" />
<text x="410.0" y="34.0" text-anchor="middle" font-size="13" font-weight="600" fill="#111827">4</text>
<text x="410.0" y="278" text-anchor="middle" font-size="12" fill="#374151">Elevated permissions</text>
<circle cx="730.0" cy="195.0" r="18" fill="#bfdbfe" stroke="#2563eb" stroke-width="2" fill-opacity="0.9" />
<text x="730.0" y="199.0" text-anchor="middle" font-size="13" font-weight="600" fill="#111827">1</text>
<text x="730.0" y="278" text-anchor="middle" font-size="12" fill="#374151">Waive MFA permission instances</text>
<text x="26" y="140.0" text-anchor="middle" font-size="13" fill="#374151" transform="rotate(-90 26 140.0)">Occurrences (count)</text>
<text x="410.0" y="342" text-anchor="middle" font-size="13" fill="#374151">MFA issue category</text>
</svg>

- **Lack of MFA options:** 2 occurrence(s) - Disabled built-in authenticator and hardware key options.
- **Elevated permissions:** 4 occurrence(s) - Privileged internal users in phishing-resistant MFA scope.
- **Waive MFA permission instances:** 1 occurrence(s) - Users with MFA bypass / waiver assignments.

---

## Configurations
> **Section score:** 1/4 passing | ❌ 3 fail | ℹ️ 2 info

- **Security settings**
  - ❌ Direct UI MFA required: `False`
  - ❌ Built-in authenticator enabled: `False`
  - ❌ Security key / U2F enabled: `False`
  - ℹ️ Lightning Login enabled: `True`
  - ℹ️ SMS identity enabled: `True`
- **Single sign-on settings**
  - ℹ️ SAML login enabled: `False`
  - ℹ️ Multiple SAML configs enabled: `True`
  - ℹ️ Login with Salesforce credentials disabled: `False`
---

## Checks
> **Section score:** 1/6 passing | ❌ 5 fail

- ❌ **FAIL**: Require MFA for all direct UI logins [False]
- ❌ **FAIL**: Built-in authenticator allowed [False]
- ❌ **FAIL**: Physical security key (U2F/WebAuthn) allowed [False]
- ❌ **FAIL**: Users with MFA bypass / waiver assignments detected [1]
- ❌ **FAIL**: Privileged users exist but phishing-resistant MFA methods are not enabled in org settings [4]
- ✅ **PASS**: No SAML SSO configuration detected in audited metadata
---

## User Summary
> **Section score:** 1/4 passing | ❌ 1 fail | ⚠️ 2 warning

- Active internal users: 9
- Privileged internal users: 4
- Users with bypass assignments: 1
- Users with permission-based UI MFA: 0
- SAML SSO configs: 0
- Per-user MFA methods unavailable: Current querying user does not have Manage MFA in API (PermissionsManageTwoFactor).
---

## Users
> **Section score:** 0/3 passing | ❌ 1 fail | ⚠️ 2 warning

### Privileged Users
- **Dale Dowdie** `<ddowdie@intellitech.net>`
  - Profile permission: Modify All Data
  - Profile permission: View All Data
  - Profile permission: Customize Application
  - Profile permission: Author Apex
- **Rick Rice** `<rick@intellitech.net>`
  - Profile: System Administrator
  - Profile permission: Modify All Data
  - Profile permission: View All Data
  - Profile permission: Customize Application
  - Profile permission: Author Apex
  - Permission set 'ScopingViewAll': View All Data
  - Permission set 'Wave Analytics Trailhead Admin': Customize Application
- **Integration User** `<integration@00d1u0000014x5duau.com>`
  - Profile permission: View All Data
- **Platform Integration User** `<cloud@00d1u0000014x5duau>`
  - Permission set 'Data Cloud Salesforce Connector': View All Data, Customize Application

### Users With MFA Bypass Assignments
- **Chatter Expert** `<chatty.00d1u0000014x5duau.b6tvwtniwrax@chatter.salesforce.com>`
  - Profile: Chatter Free User

### Users Not Covered If Org-Wide UI MFA Is Off
- **Dale Dowdie** `<ddowdie@intellitech.net>`
- **Jeff Jeffries** `<jeff@intellitech.net.crm>`
- **Jane Jacobs** `<jane@intellitech.net.com>`
- **Rick Rice** `<rick@intellitech.net>`
- **Integration User** `<integration@00d1u0000014x5duau.com>`
- **Security User** `<insightssecurity@00d1u0000014x5duau.com>`
- **Chatter Expert** `<chatty.00d1u0000014x5duau.b6tvwtniwrax@chatter.salesforce.com>`
- **Platform Integration User** `<cloud@00d1u0000014x5duau>`
- **Flow Test** `<flowtest@flowtest.org>`
---

## Manual Review
> **Section score:** 0/1 passing | ⚠️ 1 warning

- Actual user MFA method enrollment: The standard sf CLI surfaces org settings and permission assignments cleanly, but user-level registered MFA methods are not consistently queryable through stable CLI-accessible objects.