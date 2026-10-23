# ioNote

Simple, fast, private notes. Works offline and installs as an app.

Live: https://ionote.github.io

## Features

- Offline (service worker)
- Installable PWA
- Optional passcode lock, AES-256-GCM, PBKDF2 key derivation
- Light, dark, system theme
- Pin, search, export, import
- No tracking, no external requests

## Deploy

1. Create the organization `ionote`.
2. Create a public repository named `ionote.github.io`.
3. Upload the files in this folder to the repo root.
4. Settings, Pages, Deploy from a branch, `main`, `/ (root)`.
5. Open https://ionote.github.io

## Install on Android

Use Chrome, menu, **Install app**. Do not use **Add to Home screen**, it makes a shortcut.
If you installed a shortcut before, remove it first, then clear site data for the domain and reload.

## Local test

```
python -m http.server 8080
```
