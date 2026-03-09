=== Passkey Login ===
Contributors: passkey-login
Tags: passkey, webauthn, security, login, multisite
Requires at least: 6.3
Tested up to: 6.9
Requires PHP: 8.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless passkey authentication (WebAuthn/FIDO2) for WordPress and WordPress Multisite.

== Description ==

Passkey Login provides secure passkey-based login while preserving existing WordPress password login.

Features include:

* Passkey registration and authentication (WebAuthn/FIDO2)
* WordPress Multisite network support
* Network admin settings and audit log
* User profile passkey management
* Secure REST API endpoints under `/wp-json/passkey-login/v1`
* Password login remains available

== Installation ==

1. Upload the plugin to `/wp-content/plugins/passkey-login/`.
2. Activate it from the Plugins screen (or network activate in multisite).
3. Configure settings from the site admin and network admin screens.

== Changelog ==

= 1.0.0 =
* First public release.
* Passwordless passkey login for WordPress and Multisite.
* User profile passkey management (add/delete).
* Network settings, RP ID override, and audit log.
* REST API endpoints for registration and authentication.
