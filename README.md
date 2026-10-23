# ioNote

A calm, private notes app that works offline and installs on your device.

## Features
- Create, edit, search and pin notes
- Light, dark and system themes
- Optional passphrase encryption and automatic lock
- Notes stay on your device; no account, server, analytics or external requests

## Privacy
Notes are stored in this browser on this device. Without encryption they are stored as plain text and protected by your device. With encryption enabled, the key is derived from your passphrase and held in memory only while the app is unlocked. A forgotten passphrase cannot be recovered. Clearing browser data may permanently erase notes.

## Deploy
1. Create a public repository named `ionote.github.io` in the `ionote` organization.
2. Upload these files to the repository root.
3. In Settings → Pages, select Deploy from a branch, `main`, `/ (root)`.
4. Enable two-factor authentication on the account and organization, and protect `main`. Anyone who can push can change the code that handles your passphrase.

## Install on Android
In Chrome, open the menu and choose **Install and create shortcut**, then tap **Install**. Choosing **Create shortcut** makes a browser shortcut rather than a full app.

## Upgrading from the PIN version
This version has no PIN. Notes locked with the old PIN cannot be opened here. Turn the lock off in the old version before updating, or the app will offer to erase them.

## Local test
```
python -m http.server 8080
```
