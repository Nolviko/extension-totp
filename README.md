# Two-step verification (TOTP) for Nolviko

Official [Nolviko](https://github.com/Nolviko/nolviko) extension: members protect their account with a six-digit code from an authenticator
app (Google Authenticator, Microsoft Authenticator, 2FAS, Aegis, password managers, ...).

## Features

- Setup page with a QR code (generated locally, no outside service) and a manual key
- Ten single-use recovery codes, shown once; new ones on request
- The code is asked after the password and in the administrator's password confirmation
- Turning it off needs the password and a code; members get an email on every change
- Administrators can require it per group (permission *Must use two-step verification*) and turn it off for a
  member who lost the phone
- Standard TOTP (RFC 6238): 30-second codes, one step of clock drift, every code works once

The secret is stored by Nolviko core, sealed with a key derived from the site secret. If the extension is turned
off, members sign in with their password alone and the admin dashboard says how many are affected.

## Installation

1. Download the latest `nolviko-ext-nolviko-totp-<version>.zip` from this repository's **Releases** page, and copy
   the SHA-256 checksum shown next to it.
2. In your forum: **Admin → Extensions → Upload**, choose the ZIP, paste the SHA-256 and confirm that you trust
   the package.
3. Install and enable it. Updates work the same way: upload the newer ZIP; the forum turns the extension off,
   replaces its files and turns it on again. Your settings and data are kept.

Requires [Nolviko](https://github.com/Nolviko/nolviko) 0.1.0-beta.4 or newer (older versions of this package work with earlier betas). Updates appear in the admin panel. Disabling the extension keeps its data.

## Development

The package contains `extension.json`, `LICENSE`, `src/`, `translations/`; `tests/` and this README
stay in the repository. The extension uses only Nolviko core classes and PHP's standard library — no Composer
packages of its own.

Tests run against a Nolviko core checkout with its development dependencies:

```bash
php <nolviko-dev-vendor>/bin/phpunit --bootstrap <nolviko-dev-vendor>/autoload.php tests
```

Code style follows the core project (PSR-12, 120 columns). All text goes through `translations/en.json` and
`translations/tr.json`.

## License

[Apache License 2.0](LICENSE), like Nolviko itself.
