# Security

Do not include passwords, API tokens, configured installation codes, private configuration, books, or logs in public reports.

Before deploying, read the security boundaries in README.md. Configuration HTTP protection is mandatory; direct book access is permitted by default and is a deployment choice. The installation checks verify the configured URL at setup time, not every possible alias or later server change.

For a suspected vulnerability, use the repository's private vulnerability reporting facility if available. If it is unavailable, open an issue requesting a private contact without including exploit details or secrets.
