# Security

Deploy with HTTPS and a maintained PHP release. Only use private storage outside every served web root. Keep PHP under a dedicated non-root account, restrict the installer while it is unconfigured, and disable public aliases or script execution in any storage path. The implementation assumes trusted local administrators, filesystem ancestors and sibling services.

Account credentials, activation digests, API token digests, the subscription derivation key and share records are private state. Keep them out of logs, public backups and version control. Reverse proxies/CDNs must not log Authorization or raw query strings, and must not cache protected content. Use trusted proxy configuration for HTTPS and client IP restoration.

Public subscription URLs are bearer capabilities. They are intentionally short to allow reader entry, protected by invalid-attempt limits, and meant for personal sharing. Forwarding the full link forwards its access. Do not use these links to distribute highly sensitive material. Expiry and revocation apply on new requests, not to offline copies.

Upload and metadata limits reduce resource consumption but do not replace web server limits, OS quotas or monitoring. Uploaded EPUB validation does not replace antivirus or EPUBCheck. Read with a maintained e-reader, and do not render book HTML under the application origin.

Please report security issues privately through GitHub's security reporting interface if enabled.

Do not export private RBAC metadata, which includes account and role mappings and upload-token digests. Personalized Agent setup text intentionally contains an upload-only secret, unlike the generic Skill download. Paste it only into the intended agent environment. Revoke its credential in **CLI / API & upload Skill** if you stop using that agent. A folder-scoped token does not authenticate OPDS or website reads. The verification endpoint checks the token without making writes.
