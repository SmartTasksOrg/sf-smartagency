# Security policy

SmartAgency 0.1.1 is experimental software. Before release it had one code review by a separate AI
reviewer that did not write the code. It has had no independent human audit.
[README "Status"](README.md#status) says what is tested and what is not.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Report privately through GitHub: open <https://github.com/SmartTasksOrg/sf-smartagency>, go to the
**Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Only
the maintainers can read the report.

Do not open a public issue, pull request or discussion for a vulnerability, and do not put a working
exploit in one.

If the Security tab shows no "Report a vulnerability" button, private reporting is switched off. Open a
public issue that says only "I have a security report; please enable private vulnerability reporting",
with no details, and wait for a maintainer.

## What to include

- The version (`sf-smartagency --version`) and your platform.
- The smallest input that shows the problem, and what you expected.

Remove real secrets, tokens and personal data from what you send.

## Packages that pretend to be SmartAgency

The only package names the maintainers publish are listed with `"registered": true` in
[names.json](names.json). Official releases are built by `.github/workflows/release.yml` in
`SmartTasksOrg/sf-smartagency` and published with trusted publishing, so each file carries a provenance
attestation that names this repository and that workflow.

A package on any registry that uses this project's name but is not listed there, or a release file
without that provenance, is not ours. Report it through the private form above, and to the registry
(PyPI: "Report project as malware" on the project page).

## What to expect

- An answer in the private report. No response time is promised; this is a small project without a
  security team on call.
- A confirmed issue is fixed in a new release, announced in `CHANGELOG.md` and in a GitHub security
  advisory, with credit to the reporter unless they ask not to be named.
- There is no bug bounty.

## Scope

In scope: the code in this repository and its build and release files. Especially:
- an action allowed although a contract, the ledger or a limit should deny it, or an escalation skipped;
- a contract, ledger entry or registry entry accepted with a bad or missing signature, an untrusted key, or a
  broken chain;
- a revocation, suspension or supersession that does not take effect;
- input that crashes the monitor or the command line, or reaches the terminal unescaped;
- a private key written with loose permissions or printed.

Out of scope (docs/threat-model.md): an agent that acts without asking the monitor; a stolen issuer key or
write access to the registry; contracts that are valid but unwise; the host clock.
