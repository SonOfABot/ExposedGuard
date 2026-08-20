# ExposedGuard

A browser extension that checks whether the sites you visit publicly expose their .git directory, .env files, or references to them and warns you.

Runs on Firefox (desktop + Android), Chrome, Edge, Brave, Opera and other
Chromium browsers. Manifest V3, one codebase for all browsers:
`browser-polyfill.min.js` (Mozilla's official
[webextension-polyfill](https://github.com/mozilla/webextension-polyfill))
defines the promise-based `browser` API on Chromium (Firefox has it natively).

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


