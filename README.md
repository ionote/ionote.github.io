# ioNote

Simple, fast, private notes. Works offline and installs as an app.

Live: https://ionote.github.io

## Features

- Offline (service worker), installable PWA
- Optional encryption with a passphrase (AES-256-GCM, PBKDF2-SHA256 600,000 iterations)
- Auto-lock when the app is left for a chosen time
- Encrypted backups saved as a file, import merges notes
- Pin, search, undo delete, light, dark and system themes
- No account, no server, no analytics, no external requests

## Privacy model

Notes live in the browser storage of your device. With encryption off they are stored as plain text, protected only by your phone lock. With encryption on, the key is derived from your passphrase, kept in memory only, and dropped when the app locks. There is no recovery: a forgotten passphrase means lost notes. Keep a backup.

## Deploy

1. Create a public repository named `ionote.github.io` in the `ionote` organization.
2. Upload these files to the repo root.
3. Settings, Pages, Deploy from a branch, `main`, `/ (root)`.
4. Enable two-factor authentication on the account and organization, and protect `main`. Anyone who can push can change the code that handles your passphrase.

## Install on Android

Chrome, menu, **Install and create shortcut**, then **Install**. Choosing **Create shortcut** gives a plain browser shortcut.

## Upgrading from the PIN version

This version has no PIN. Notes locked with the old PIN cannot be opened here. Turn the lock off in the old version, or export, before updating. Otherwise the app offers to erase them.

## Local test

```
python -m http.server 8080
```
