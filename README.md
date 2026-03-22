# Securekey Login

Securekey Login adds passwordless passkey authentication (WebAuthn/FIDO2) to WordPress 6.3+ and PHP 8.2+, with first-class multisite support.

## Features

- Passkey registration and authentication ceremonies
- Single-site and multisite network support
- Per-site credential/challenge storage
- Network-wide security audit log
- REST API (`/wp-json/securekey-login/v1`)
- User profile passkey management UI
- Password login remains available as a fallback

## Release

- Current version: `1.0.0`
- First public release date: `2026-03-09`

## Development

```bash
composer install
composer lint
```

## Security Notes

- Existing password login remains available unless explicitly disabled by administrators.
- Sensitive material (private keys, raw attestation objects) is never logged.
