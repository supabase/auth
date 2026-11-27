# Security Policy

Thank you for helping keep Supabase Auth (GoTrue fork) and its users safe.

## Reporting a vulnerability

Please report suspected vulnerabilities through our HackerOne program:
<https://hackerone.com/supabase>. Please do not open public GitHub issues or
pull requests for security problems.

This repository contains the Supabase Auth server, the service behind Supabase
Auth: sign-up and sign-in, sessions and tokens, MFA, OAuth and SSO providers,
and the email and phone flows that go with them. It runs on the hosted Supabase
platform and is also run by people who self-host it. We accept reports for both,
and we triage them differently (see "Hosted vs. self-hosted" below).

## What we consider a vulnerability

In general, we want to hear about anything that lets an attacker break the
security guarantees Auth makes to a user or a project: gaining access to an
account, session, token or other authentication data they should not have,
acting with more privilege than they were granted, or crossing a boundary
between users, projects or tenants. The attacker should not need the victim's
credentials or project privileges, and the problem should be present in a
default or documented configuration.

Examples of what this includes (these are illustrations, not a complete list):

- **Account takeover or session theft.** Taking over another user's account, or
  obtaining a session, access token or refresh token for an account the
  attacker does not control.
- **Authentication and MFA bypass.** Reaching AAL2 without completing a second
  factor, minting a session without a valid credential, or using a token on an
  endpoint it was not issued for. Sibling code paths that skip a check enforced
  elsewhere (for example password policy, ban checks or AAL checks) are in
  scope.
- **Exposure of authentication data.** Gaining access to auth codes, tokens,
  one-time codes or secrets that belong to someone else, including through
  redirect handling. Defeating redirect validation so that codes or tokens
  reach an attacker-controlled origin counts, including URL parsing mismatches
  and allowlist comparisons that ignore scheme or port.
- **Incorrect identity linking.** Trusting an email the provider did not
  verify, or ending up with two accounts for one identity.
- **One-time token misuse.** Redeeming an OTP, magic link, recovery or invite
  token more than once, or redeeming one that was never issued.
- **Cross-tenant access.** One project's keys, JWKS or configuration being
  accepted for another project.
- **Bypass of a documented security control.** A session-lifetime or
  inactivity setting that is not enforced, a rate limit that can be defeated on
  a default configuration, or a secret exposed in an API response, log line or
  error message to someone who should not see it.
- **SSRF against the hosted service.** Reaching internal services through an
  outbound request feature by bypassing the protections the hosted service
  applies.

## What we do not consider a vulnerability

These come up often. Reports that rely on them will normally be closed as
informative or not applicable.

**Behavior that is by design**

- **Access tokens stay valid until they expire.** Access tokens are stateless
  JWTs. After logout, a password change or a session revocation, the refresh
  token is revoked, but an already-issued access token keeps working until its
  `exp`. Shorten the JWT expiry in your project settings if this matters to
  you. A report needs to show a token working *after* its expiry to be
  accepted.
- **Refresh token reuse interval.** Replaying a refresh token inside the
  configured reuse interval is deliberate, to tolerate client and network
  retries. Racing that window is not a vulnerability unless it allows something
  the attacker could not already do with a stolen token.
- **Actions allowed at AAL1.** A session that has only completed the first
  factor can perform the actions the AAL model allows. Reaching AAL2 after
  verifying any one enrolled factor is documented behavior. A report should show
  an AAL1 session reaching something that requires AAL2.
- **TOTP time-step tolerance.** Accepting the code from an adjacent time step
  follows RFC 6238 and is intended.
- **`user_metadata` is user-editable.** Users can write to their own
  `user_metadata`, and our documentation says not to base authorization on it.
  Use `app_metadata` for that. Applications that trust `user_metadata` have a
  bug in the application, not in Auth.
- **Customer-controlled configuration.** The Site URL, redirect URL allowlist,
  and email templates are set by project owners. Reports that start with the
  attacker changing these are reports about someone who already has the
  project. The `**` globstar redirect pattern matches broadly by design, is
  documented for local development and deployment previews, and should not be
  used in production. A bypass of an *exact* redirect URL is in scope.
- **Reusing a password.** Auth does not keep password history. Leaked-password
  protection is the supported control.
- **Login CSRF through OAuth without further impact.** A correctly validated
  `state` parameter prevents CSRF. Tricking someone into signing in to the
  attacker's own account, with no data exposure or takeover shown, is not
  accepted.
- **Standard OAuth parameters in redirect URLs.** Codes and tokens in URLs are
  part of the protocol. A report must show them reaching an untrusted party.

**Prerequisites that make the attack pointless**

- The attacker needs a valid access token, refresh token or active session of
  the victim. Possessing the credential already grants what you describe.
- The attacker needs the victim's mailbox, or a recovery link or OTP they can
  only get from the mailbox. This already grants account recovery.
- The attacker needs admin or service-role access, or control of the project's
  Auth configuration.
- Response tampering through your own intercepting proxy. This changes what you
  see, not what the server does.

**Missing hardening with no demonstrated exploit**

- A CORS response of `Access-Control-Allow-Credentials: true` together with a
  wildcard origin. Browsers do not send credentials in that combination. Show a
  working cross-origin credentialed read.
- Lack of account lockout, or a race that lets slightly more attempts through
  than the per-OTP limit. The verify endpoints are rate limited and OTPs expire
  quickly. Show a practical brute force inside the validity window.
- A factor cap, plan limit or other convenience limit that can be exceeded with
  concurrent requests, when exceeding it has no security consequence.

**Reports that are about something else**

- Credentials in the git history of this repository that are revoked, or that
  belong to a test app with no access to anything. Show that a credential is
  live and grants access.
- Vulnerabilities in a customer's application, or in a third-party identity
  provider's behavior that its own documentation describes.
- Automated scanner output with no demonstrated impact, and reports that were
  not reproduced against a real deployment.

## Out of scope for every Supabase asset

These are excluded program-wide (see also
<https://supabase.com/.well-known/security.txt>). They are repeated here so
you do not need to leave this repository to find them.

- Clickjacking on pages with no sensitive actions.
- Unauthenticated, logout and login CSRF.
- Attacks requiring MITM or physical access to a user's device.
- Attacks requiring social engineering.
- Any activity that could lead to the disruption of our service (DoS).
  This means volumetric attacks, load testing and flooding. A vulnerability in
  our code that lets an unprivileged attacker crash a service or exhaust
  resources for other users or tenants is in scope. Denial of service that only
  affects the attacker's own project, or that needs admin or owner privileges,
  is not.
- Content spoofing and text injection issues without showing an attack vector,
  or without being able to modify HTML/CSS.
- Email spoofing.
- Missing DNSSEC, CAA or CSP headers.
- Lack of Secure or HttpOnly flags on non-sensitive cookies.
- Dead links.
- User enumeration.

## Known and documented behavior

These are described in our public documentation. Please check them before
reporting.

- **Rate limiting depends on a trusted proxy.** If you configure
  `GOTRUE_RATE_LIMIT_HEADER`, Auth trusts the named header to be set by your
  reverse proxy. A client that sends or omits that header on a deployment
  without such a proxy is a configuration problem. The trusted proxy is the
  security boundary. If you can show a bypass against a hosted Supabase project,
  that is in scope.
- **Outbound requests and self-hosting.** Auth makes outbound requests to
  operator-configured endpoints such as SAML metadata URLs and OIDC providers.
  Self-hosted deployments may legitimately need to reach internal networks, so
  limiting egress at the network level is the documented mitigation. Hosted
  Supabase blocks internal and metadata addresses, and we welcome reports that
  bypass those protections.
- **Providers that issue unverified email claims.** Some providers, such as
  Azure with certain tenant configurations, can return emails the user has not
  verified. Developers mitigate this by following the provider guidance in our
  docs, for example by validating the `xms_edov` claim.

## Hosted vs. self-hosted

We accept self-hosted findings when shipped defaults or the documented setup
lead to the problem, and we treat them as lower severity when the operator has
to misconfigure the deployment first, such as with a wildcard redirect URL, no
proxy in front of the rate limiter, or a default secret that was never changed.
Label your report as described in the next section.

## How to write a report that gets triaged quickly

- **Say what you tested, at the top of the report and in the title.** Use one of
  these labels, for example `[Production] ...` in the title and a "Target" line
  at the start of the description:
  - **Production**: the hosted Supabase platform, against a project you own.
    Include the project ref. Never test another customer's project.
  - **Self-hosted, default configuration**: the code in this repository run
    exactly as shipped or as our self-hosting guide describes, with no changed
    settings. Include the version or commit and how you started it.
  - **Self-hosted, custom configuration**: you changed settings, added a proxy,
    or modified code. List every setting you changed and why. We triage these
    lower unless the setting is one we recommend or document.

  Reports that do not say which of the three they are about are slower to
  triage, and are often closed with a request to retest. A finding that works
  only on a custom configuration is not a finding against production.

- **Test a real deployment.** Code reading alone is rarely enough. Static
  analysis findings need a working proof of concept against one of the targets
  above.
- **Give a short, runnable PoC.** Exact requests, a script or a screen
  recording, and the output showing the impact. Do not show a "success" that is
  only a redirect status code. Confirm that the attacker really got something
  they should not have.
- **State the attacker's starting position.** What do they already know or hold
  (an anonymous request, a leaked anon key, a victim's token, project admin)?
  Reports that quietly assume the attacker already has the victim's credentials
  are our most common reason to close.
- **Name the boundary you crossed.** Which user, project, tenant or AAL level
  could not do this before? If nothing was crossed, it is probably a hardening
  suggestion.
- **Check the docs and this file first.** If the behavior is documented, explain
  why the documented design still fails.
- **Include versions.** The Auth version or commit, and the relevant `GOTRUE_*`
  settings.
- **One issue per report.** Link variants of the same root cause instead of
  filing each variant separately.
- **Do not send unreviewed AI output.** Reports that were not reproduced by a
  human and that ignore the documentation are closed. AI-assisted analysis is
  fine when you have verified the result.
- **Respond to follow-up questions.** Reports that go quiet after we ask for a
  reproduction are closed.

## Severity

We rate severity by realistic impact on a default deployment. Issues that need
an unusual configuration, a specific timing window, or a strong prerequisite
are rated lower even when they are valid, and we may fix them as defense in
depth.

## Testing and disclosure

These are our program-wide rules. They also apply to AI agents and automated
tools acting on your behalf.

**Testing**

- Do not run automated scanners against other customers' projects. Scanners can
  run up costs for our users, can disrupt services, and our own security
  systems cannot tell hostile reconnaissance from research. If you want to run
  an automated scanner, notify security@supabase.com first and run it only on
  your own Supabase project.
- Do not attack projects that belong to other customers.
- Do not take advantage of a vulnerability you find, for example by downloading
  more data than necessary to demonstrate it, or by deleting or modifying other
  people's data.

**Disclosure**

- Do not reveal the problem to others until we have researched and fixed it and
  informed affected customers.
- If you want to share your research publicly (a conference, a blog or any
  other public forum), send us a draft for review and approval at least 30 days
  before the publication date. Do not include data about Supabase customer
  projects, customers' data, or information about Supabase employees,
  contractors or partners.

**What we promise**

- We will respond to your report within 5 business days with our evaluation and
  an expected resolution date.
- If you have followed these instructions, we will not take legal action against
  you in regard to the report.
- We will handle your report with strict confidentiality and will not pass on
  your personal details to third parties without your permission.
- We will keep you informed of our progress.
- In public information about the problem, we will name you as the discoverer
  unless you prefer otherwise.
