# Salesforce MFA Audit Report

## Org
- **Alias:** `MyOrg`
- **Username:** `rick@intellitech.net`
- **Instance:** `https://2600-dev-ed.my.salesforce.com`

## Configurations
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

## Checks
- ❌ **FAIL**: Require MFA for all direct UI logins [False]
- ❌ **FAIL**: Built-in authenticator allowed [False]
- ❌ **FAIL**: Physical security key (U2F/WebAuthn) allowed [False]
- ❌ **FAIL**: Users with MFA bypass / waiver assignments detected [1]
- ❌ **FAIL**: Privileged users exist but phishing-resistant MFA methods are not enabled in org settings [4]
- ✅ **PASS**: No SAML SSO configuration detected in audited metadata

## User Summary
- Active internal users: 9
- Privileged internal users: 4
- Users with bypass assignments: 1
- Users with permission-based UI MFA: 0
- SAML SSO configs: 0

## Users
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

## Manual Review
- Actual user MFA method enrollment: The standard sf CLI surfaces org settings and permission assignments cleanly, but user-level registered MFA methods are not consistently queryable through stable CLI-accessible objects.