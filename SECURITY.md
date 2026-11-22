# Security

Do not include passwords, API tokens, private configuration, books, or logs in public reports.

Before deploying, read the security boundaries in README.md. Keep configuration outside the document root, or apply HTTP protection rules for site-local configuration. Site-local book storage permits direct book access by default; separate storage is outside the website. Do not expose private storage through other aliases or download handlers. The installation checks verify the configured URL at setup time, not every possible alias or later server change.

For a suspected vulnerability, use the repository's private vulnerability reporting facility if available. If it is unavailable, open an issue requesting a private contact without including exploit details or secrets.
