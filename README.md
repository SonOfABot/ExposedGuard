# ExposedGuard

A browser extension that checks whether the sites you visit publicly expose their .git directory, .env files, or references to them and warns you.

Exposed Guard is on Firefox extension store (it's the main browser i use hence I pushed it there), you can build locally and upload but I should push to all browsers this month


<img width="374" height="641" alt="image" src="https://github.com/user-attachments/assets/2eb30fba-3abf-45d4-952f-84e1c1fc1850" />


One shared codebase (`src/`), one build per browser (`dist/`), produced by
`build.py`:

| Build | Manifest | Browsers |
|---|---|---|
| `dist/firefox/` | MV2 (`background.scripts`) | Firefox desktop 140+, Firefox for Android 142+ |
| `dist/chrome/` | MV3 (`background.service_worker`) | Chrome 102+ |
| `dist/brave/` | MV3 | Brave |
| `dist/opera/` | MV3 | Opera |
| `dist/edge/` | MV3 | Edge |

Firefox stable does not support MV3 service workers (hence the MV2 build);
Chromium does not accept MV2 (hence the MV3 build). The JS is identical in
both - `browser-polyfill.min.js` (Mozilla's official
[webextension-polyfill](https://github.com/mozilla/webextension-polyfill))
provides the promise-based `browser` API on Chromium, and `background.js`
loads it via `importScripts` only when running as a service worker.

## What it checks (~50 probes)

| Category | Examples | Severity | Validation (anti false-positive) |
|---|---|---|---|
| Version control | `/.git/HEAD`, `/.git/config`, `/.git/index`, `/.git/packed-refs`, `/.git/logs/HEAD`, `/.svn/entries`, `/.svn/wc.db`, `/.hg/requires`, `/.bzr/branch-format` | Medium-High | `ref: refs/...`, `[core]`+`repositoryformatversion`, `DIRC`/SQLite magic bytes, ... |
| Environment files | `/.env` + 8 variants (`.local`, `.production`, `.development`, `.staging`, `.test`, `.backup`, `.old`, `.save`) | Critical | must be `KEY=value` style, not HTML |
| Credentials | `/.aws/credentials`, `/.netrc`, `/.ssh/id_rsa`, `/id_rsa`, `/.npmrc`, `/.htpasswd`, `/.vscode/sftp.json`, `/sftp-config.json` | High-Critical | key hashes, `PRIVATE KEY`, password fields |
| Source/config backups | `/wp-config.php.bak/.old/.txt/.save`, `/config.php~`, `/config.php.bak/.old`, `/.htaccess`, `/web.config`, `/WEB-INF/web.xml`, CI files | Low-Critical | PHP source markers, `DB_PASSWORD`, XML roots |
| Backup archives & dumps | `/backup.zip`, `/site.zip`, `/www.zip`, `*.tar.gz`, `/db.sql`, `/dump.sql`, `/backup.sql`, `/database.sql` | High | `PK\x03\x04` / gzip magic bytes, `CREATE TABLE` |
| Debug leaks | `/phpinfo.php`, `/info.php`, `/server-status`, `/.idea/workspace.xml`, `/.DS_Store` | Low-Medium | `PHP Version`, `Apache Server Status`, `$PROJECT_DIR$`, `Bud1` magic |

It also scans the page source (markup, attributes, inline scripts) for
references to `.git/`, `.svn/`, `.env`, private keys and DB config - shown as
weaker "reference" findings.

Probes run **without cookies** (`credentials: "omit"`), so they detect what an
anonymous visitor can see. Redirects to a different path (SPA catch-alls) are
discarded. Response bodies are capped at 256 KB, so probing `backup.zip` never
downloads the whole archive - just enough to check magic bytes.

## Features

- Automatic check on every page load (re-checks a host at most every 10 min)
- Toolbar badge: red count = exposed files, amber `?` = references only
- Desktop notification when a new exposure is found
- Popup: current-site findings with severity-colored cards and content
  preview, manual re-check, cross-site history, "clear all"
- Results persist in `storage.local` across restarts

## Install for development

Run `python build.py` first (see below), then load the matching `dist/`
folder:

**Firefox desktop:** `about:debugging#/runtime/this-firefox` ->
**Load Temporary Add-on...** -> pick `dist/firefox/manifest.json`

**Chrome / Edge / Brave / Opera:** open `chrome://extensions` (or
`edge://extensions`, `brave://extensions`, `opera://extensions`) -> enable
**Developer mode** -> **Load unpacked** -> pick `dist/<browser>/`

**Firefox for Android:** Android only installs signed extensions from AMO:

- **Simplest:** sign the firefox zip on AMO as *self-distributed*, then
  install the signed `.xpi` via
  `web-ext run --target=firefox-android` over USB debugging.
- **Nightly/Beta:** create a custom add-on collection on AMO and point
  Nightly's "Custom Add-on collection" setting at it.

The Firefox manifest already includes `gecko_android` (min 142, where the
required `data_collection_permissions` key is supported) and the popup is
mobile-sized (viewport meta, `max-width: 480px`). On AMO, Android availability
is enabled per-version: in the Developer Hub version page, keep the
"Firefox for Android" platform option checked when uploading.

**Safari:** convert the chromium build with Apple's tool on macOS:
`xcrun safari-web-extension-converter dist/chrome`

## Building

```sh
python build.py
```

This regenerates every `dist/<browser>/` folder from `src/` and creates an
upload zip per browser: `dist/exposed-guard-<version>-<browser>.zip`.
Each zip has `manifest.json` at its root (a store requirement). Edit shared
code in `src/`, then rebuild. To bump the version, edit both
`src/manifest.firefox.json` and `src/manifest.chromium.json` - the build
fails if they disagree.

Store notes:

- **AMO (Firefox):** upload the firefox zip -> listed (public) or
  self-distributed.
- **Chrome Web Store / Edge Add-ons / Opera add-ons:** upload the matching
  MV3 zip. Chrome requires a $5 one-time developer account; the broad
  `host_permissions` will prompt a justification field during review - state
  that the extension fetches well-known paths on visited sites to detect
  exposed files.

## Customizing the target list

Edit `CHECK_TARGETS` at the top of `src/background.js` - each entry is a
path, a severity (`critical` / `high` / `medium` / `low`), and a
`validate(status, text, bytes)` function. Shared validators (`isEnv`,
`isZip`, `isSqlDump`, `isWpConfig`, ...) cover the common patterns.

## Test lab

`test-site/` contains a Docker lab: a deliberately vulnerable site (all
exposures present) and a "clean" SPA whose catch-all route answers every
path with `200 + HTML` - proving the false-positive rejection works.

```sh
cd test-site
docker build -t exposed-guard-test .
docker run -d --name eg-test -p 8080:8080 -p 8081:8081 exposed-guard-test
# vulnerable: http://localhost:8080  |  clean SPA: http://localhost:8081
docker stop eg-test   # when done
```

## Legal note

Only probe sites you own or are authorized to test. Exposed `.git`/`.env`
data belongs to the site operator - report it (e.g. via their
`security.txt`) instead of downloading it.
