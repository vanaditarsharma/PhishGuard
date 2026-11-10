# Contributing

Thanks for your interest in improving PhishGuard.

## Before opening a change

- Keep the project defensive and suitable for controlled analysis.
- Do not add real credentials, API keys, private emails or personal data.
- Do not add datasets unless their licence, source and permitted use are documented.
- Do not describe synthetic test results as real-world detection performance.
- Avoid automatic URL fetching or attachment execution.

## Development workflow

1. Create a branch for your change.
2. Create and activate a Python virtual environment.
3. Install dependencies with `python -m pip install -r requirements.txt`.
4. Run the test suite with `python -m pytest -q`.
5. Describe the change, tests run and any known limitations in your pull request.

## Reporting issues

Include the operating system, Python version, steps to reproduce and relevant error output. Remove email addresses, tokens, message contents and other sensitive information before sharing logs or samples.
