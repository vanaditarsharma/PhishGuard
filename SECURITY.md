# Security Policy

## Scope

PhishGuard is an academic and local-first defensive email-analysis project. It is not a production email gateway or a hosted service.

## Reporting a vulnerability

Please do not publish live credentials, private email samples, API tokens or exploitable personal data in a public issue. For a sensitive report, contact the repository maintainer privately through the contact method listed on the GitHub profile.

Include:
- A concise description and potential impact.
- Affected version or commit.
- Reproduction steps using a safe, local test fixture.
- Any suggested mitigation.

## Safe-use boundaries

- Run the application locally or in an isolated test environment.
- Do not expose the default local demo API to the public internet.
- Treat uploaded emails, headers, URLs and attachments as untrusted input.
- Do not open suspicious links or execute suspicious attachments to test this project.
- External reputation lookups require explicit consent because indicators are sent to third-party services.
