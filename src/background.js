// Cross-browser polyfill loading:
// - Chromium MV3: this file runs as a service worker, so importScripts exists
//   and loads the polyfill (which defines the promise-based `browser` API).
// - Firefox MV2: the polyfill is already loaded via background.scripts in the
//   manifest, and importScripts does not exist in a background page, so this
//   line is skipped.
if (typeof importScripts === "function" && typeof globalThis.browser === "undefined") {
  importScripts("browser-polyfill.min.js");
}

"use strict";

/*
 * ExposedGuard - background worker (MV3 service worker)
 * On every page load, probes the site origin for publicly exposed
 * .git metadata and .env files, validates the responses to avoid
 * false positives (SPA catch-all routes, error pages, etc.),
 * stores findings per host, badges the toolbar icon and notifies.
 */

/* ------------------------------------------------------------------ */
/* Target list                                                         */
/* ------------------------------------------------------------------ */

function looksLikeHtml(body) {
  return /^\s*<!doctype html/i.test(body)
      || /^\s*<html[\s>]/i.test(body)
      || /<(head|body|div|script|title)[\s>]/i.test(body.slice(0, 2000));
}

function looksLikeEnv(body) {
  if (!body || looksLikeHtml(body)) return false;
  const lines = body.split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith("#"));
  if (lines.length === 0) return false;
  const kv = lines.filter(l => /^[A-Za-z_][A-Za-z0-9_.\-]*\s*=/.test(l));
  // At least one KEY=value line, and most non-comment lines look like assignments.
  return kv.length >= 1 && kv.length / lines.length >= 0.5;
}

/* Binary helpers: probes read a capped byte prefix so magic bytes can be
 * checked without downloading whole backup archives. */
function hasMagic(bytes, magic) {
  if (!bytes || bytes.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) return false;
  }
  return true;
}

function startsWithText(bytes, str) {
  return hasMagic(bytes, Array.from(str, c => c.charCodeAt(0)));
}

const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04];  // "PK\x03\x04"
const GZIP_MAGIC = [0x1f, 0x8b];

/* Shared validators. Each receives (status, text, bytes). */
const isEnv = (s, t) => s === 200 && looksLikeEnv(t);
const isZip = (s, t, b) => s === 200 && hasMagic(b, ZIP_MAGIC);
const isGzip = (s, t, b) => s === 200 && hasMagic(b, GZIP_MAGIC);
const isSqlDump = (s, t) => s === 200
  && /(CREATE TABLE|INSERT INTO|DROP TABLE|MySQL dump|PostgreSQL database dump)/i.test(t);
const isPrivateKey = (s, t) => s === 200 && /PRIVATE KEY/.test(t) && !looksLikeHtml(t);
const isWpConfig = (s, t) => s === 200
  && /(DB_PASSWORD|DB_NAME|AUTH_KEY|wp-settings)/.test(t);
const isPhpConfig = (s, t) => s === 200 && /<\?php/.test(t)
  && /(password|passwd|DB_|mysql)/i.test(t);
const isPhpInfo = (s, t) => s === 200 && /(phpinfo\(\)|PHP Version)/i.test(t);
const isSftpJson = (s, t) => s === 200 && /"host"\s*:/.test(t) && /"password"\s*:/.test(t);

const CHECK_TARGETS = [
  /* ---- Version control systems ---- */
  { path: "/.git/HEAD", type: "vcs", severity: "high",
    validate: (s, t) => s === 200 && (/^ref: refs\/[A-Za-z0-9_\-\/.]+/m.test(t)
        || /^[0-9a-f]{40}\s*$/m.test(t.trim())) },
  { path: "/.git/config", type: "vcs", severity: "high",
    validate: (s, t) => s === 200 && /\[core\]/i.test(t) && /repositoryformatversion/i.test(t) },
  { path: "/.git/index", type: "vcs", severity: "high",
    validate: (s, t, b) => s === 200 && startsWithText(b, "DIRC") },
  { path: "/.git/packed-refs", type: "vcs", severity: "high",
    validate: (s, t) => s === 200 && (t.includes("# pack-refs") || /^[0-9a-f]{40} refs\//m.test(t)) },
  { path: "/.git/logs/HEAD", type: "vcs", severity: "high",
    validate: (s, t) => s === 200 && /^[0-9a-f]{40} [0-9a-f]{40} /m.test(t) },
  { path: "/.svn/entries", type: "vcs", severity: "high",
    validate: (s, t) => s === 200 && !looksLikeHtml(t) && /^1[0-2]\s*\n/.test(t) && /\bdir\b/.test(t) },
  { path: "/.svn/wc.db", type: "vcs", severity: "high",
    validate: (s, t, b) => s === 200 && startsWithText(b, "SQLite format 3") },
  { path: "/.hg/requires", type: "vcs", severity: "high",
    validate: (s, t) => s === 200 && !looksLikeHtml(t) && /revlog|dotencode|fncache|^store$/m.test(t) },
  { path: "/.bzr/branch-format", type: "vcs", severity: "medium",
    validate: (s, t) => s === 200 && /Bazaar/i.test(t) && !looksLikeHtml(t) },

  /* ---- Environment files & credentials ---- */
  { path: "/.env", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.local", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.production", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.development", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.staging", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.test", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.backup", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.old", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.env.save", type: "secret", severity: "critical", validate: isEnv },
  { path: "/.aws/credentials", type: "secret", severity: "critical",
    validate: (s, t) => s === 200 && /\[.+\]/.test(t) && /aws_access_key_id/i.test(t) },
  { path: "/.netrc", type: "secret", severity: "critical",
    validate: (s, t) => s === 200 && !looksLikeHtml(t) && /machine\s+\S+[\s\S]*login\s+\S+/i.test(t) },
  { path: "/.ssh/id_rsa", type: "secret", severity: "critical", validate: isPrivateKey },
  { path: "/id_rsa", type: "secret", severity: "critical", validate: isPrivateKey },
  { path: "/.npmrc", type: "secret", severity: "high",
    validate: (s, t) => s === 200 && !looksLikeHtml(t) && /_auth/i.test(t) },
  { path: "/.htpasswd", type: "secret", severity: "high",
    validate: (s, t) => s === 200 && !looksLikeHtml(t)
        && /^[^:\s]+:(\$apr1\$|\{SHA\}|\$2[aby]\$|[./A-Za-z0-9]{13})/m.test(t) },
  { path: "/.vscode/sftp.json", type: "secret", severity: "high", validate: isSftpJson },
  { path: "/sftp-config.json", type: "secret", severity: "high", validate: isSftpJson },

  /* ---- Exposed source & config backups ---- */
  { path: "/wp-config.php.bak", type: "config", severity: "critical", validate: isWpConfig },
  { path: "/wp-config.php.old", type: "config", severity: "critical", validate: isWpConfig },
  { path: "/wp-config.php.txt", type: "config", severity: "critical", validate: isWpConfig },
  { path: "/wp-config.php.save", type: "config", severity: "critical", validate: isWpConfig },
  { path: "/config.php~", type: "config", severity: "high", validate: isPhpConfig },
  { path: "/config.php.bak", type: "config", severity: "high", validate: isPhpConfig },
  { path: "/config.php.old", type: "config", severity: "high", validate: isPhpConfig },
  { path: "/.htaccess", type: "config", severity: "medium",
    validate: (s, t) => s === 200 && !looksLikeHtml(t)
        && /(RewriteEngine|RewriteRule|AuthType|Require |Deny from|Allow from|Options )/.test(t) },
  { path: "/web.config", type: "config", severity: "medium",
    validate: (s, t) => s === 200 && /<configuration[\s>]/i.test(t) },
  { path: "/WEB-INF/web.xml", type: "config", severity: "high",
    validate: (s, t) => s === 200 && /<web-app[\s>]/i.test(t) },
  { path: "/.gitlab-ci.yml", type: "config", severity: "low",
    validate: (s, t) => s === 200 && !looksLikeHtml(t) && /(stages:|script:|image:)/.test(t) },
  { path: "/.travis.yml", type: "config", severity: "low",
    validate: (s, t) => s === 200 && !looksLikeHtml(t) && /(language:|script:)/.test(t) },

  /* ---- Backup archives & database dumps ---- */
  { path: "/backup.zip", type: "backup", severity: "high", validate: isZip },
  { path: "/site.zip", type: "backup", severity: "high", validate: isZip },
  { path: "/www.zip", type: "backup", severity: "high", validate: isZip },
  { path: "/backup.tar.gz", type: "backup", severity: "high", validate: isGzip },
  { path: "/site.tar.gz", type: "backup", severity: "high", validate: isGzip },
  { path: "/www.tar.gz", type: "backup", severity: "high", validate: isGzip },
  { path: "/db.sql", type: "backup", severity: "high", validate: isSqlDump },
  { path: "/dump.sql", type: "backup", severity: "high", validate: isSqlDump },
  { path: "/backup.sql", type: "backup", severity: "high", validate: isSqlDump },
  { path: "/database.sql", type: "backup", severity: "high", validate: isSqlDump },

  /* ---- Debug & info leaks ---- */
  { path: "/phpinfo.php", type: "debug", severity: "medium", validate: isPhpInfo },
  { path: "/info.php", type: "debug", severity: "medium", validate: isPhpInfo },
  { path: "/server-status", type: "debug", severity: "medium",
    validate: (s, t) => s === 200 && /(Apache Server Status|Server uptime|Total accesses)/i.test(t) },
  { path: "/.idea/workspace.xml", type: "debug", severity: "medium",
    validate: (s, t) => s === 200 && t.includes("$PROJECT_DIR$") },
  { path: "/.DS_Store", type: "debug", severity: "low",
    validate: (s, t, b) => s === 200 && startsWithText(b, "Bud1") }
];

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

const STORE_KEY = "findingsByHost";
const RECHECK_INTERVAL_MS = 10 * 60 * 1000; // auto re-check a host at most every 10 min
const inFlight = new Set();

async function getStore() {
  const data = await browser.storage.local.get(STORE_KEY);
  return data[STORE_KEY] || {};
}

async function setStore(store) {
  await browser.storage.local.set({ [STORE_KEY]: store });
}

/* ------------------------------------------------------------------ */
/* Checking                                                            */
/* ------------------------------------------------------------------ */

/* Read at most `cap` bytes of a response body, then cancel the download.
 * Prevents fetching multi-MB backup archives in full just to check magic bytes. */
async function readPrefix(res, cap) {
  if (!res.body) {
    return new Uint8Array(await res.arrayBuffer()).slice(0, cap);
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < cap) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
  } finally {
    try { await reader.cancel(); } catch (_) { /* ignore */ }
  }
  const out = new Uint8Array(Math.min(total, cap));
  let off = 0;
  for (const c of chunks) {
    if (off >= out.length) break;
    const n = Math.min(c.length, out.length - off);
    out.set(c.subarray(0, n), off);
    off += n;
  }
  return out;
}

const MAX_PROBE_BYTES = 256 * 1024;

function makePreview(bytes, text) {
  // Binary file? show a placeholder instead of mojibake.
  for (let i = 0; i < Math.min(bytes.length, 64); i++) {
    if (bytes[i] === 0) return "[binary file]";
  }
  return text.slice(0, 300);
}

async function probe(origin, target) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(origin + target.path, {
      method: "GET",
      credentials: "omit",        // probe as an anonymous visitor
      redirect: "follow",
      cache: "no-store",
      signal: controller.signal
    });
    // Redirected away from the requested path -> almost certainly a catch-all.
    try {
      if (new URL(res.url).pathname !== target.path) return null;
    } catch (_) { /* keep original result if URL parse fails */ }
    const bytes = await readPrefix(res, MAX_PROBE_BYTES);
    const text = new TextDecoder("utf-8").decode(bytes);
    if (!target.validate(res.status, text, bytes)) return null;
    return {
      path: target.path,
      type: target.type,
      severity: target.severity,
      url: origin + target.path,
      preview: makePreview(bytes, text),
      foundAt: Date.now()
    };
  } catch (e) {
    return null; // network error, timeout, CORS-style block - not a finding
  } finally {
    clearTimeout(timer);
  }
}

async function checkHost(origin, { force = false } = {}) {
  if (inFlight.has(origin)) return null;
  const store = await getStore();
  const existing = store[origin];
  if (!force && existing && (Date.now() - existing.lastChecked) < RECHECK_INTERVAL_MS) {
    return existing;
  }
  inFlight.add(origin);
  try {
    const probes = await Promise.all(CHECK_TARGETS.map(t => probe(origin, t)));
    const findings = probes.filter(Boolean);

    const hadFindings = existing && existing.findings && existing.findings.length > 0;
    const refs = (existing && existing.refs) || [];
    const entry = { findings, refs, lastChecked: Date.now() };
    store[origin] = entry;
    await setStore(store);

    if (findings.length > 0) {
      const isNew = !hadFindings
        || findings.some(f => !(existing.findings || []).some(o => o.path === f.path));
      if (isNew) notifyFinding(origin, findings);
    }
    refreshBadges();
    return entry;
  } finally {
    inFlight.delete(origin);
  }
}

/* ------------------------------------------------------------------ */
/* Notifications & badge                                               */
/* ------------------------------------------------------------------ */

const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

function notifyFinding(origin, findings) {
  const worst = findings.reduce(
    (a, f) => (SEV_RANK[f.severity] || 0) > (SEV_RANK[a] || 0) ? f.severity : a,
    "low"
  ).toUpperCase();
  const list = findings.map(f => f.path).join(", ");
  browser.notifications.create("eg-" + origin + "-" + Date.now(), {
    type: "basic",
    iconUrl: browser.runtime.getURL("icons/icon-96.png"),
    title: `ExposedGuard: ${worst} exposure on ${new URL(origin).host}`,
    message: list
  });
}

async function refreshBadges() {
  const store = await getStore();
  const tabs = await browser.tabs.query({});
  for (const tab of tabs) {
    if (!tab.url || !/^https?:/.test(tab.url)) continue;
    const origin = new URL(tab.url).origin;
    const entry = store[origin];
    const n = entry && entry.findings ? entry.findings.length : 0;
    const refOnly = !n && entry && entry.refs && entry.refs.length > 0;
    browser.action.setBadgeText({ tabId: tab.id, text: n ? String(n) : (refOnly ? "?" : "") });
    browser.action.setBadgeBackgroundColor({
      tabId: tab.id,
      color: n ? "#dc2626" : "#f59e0b"
    });
  }
}

/* ------------------------------------------------------------------ */
/* Triggers                                                            */
/* ------------------------------------------------------------------ */

browser.webNavigation.onCompleted.addListener(details => {
  if (details.frameId !== 0) return;
  if (!/^https?:/.test(details.url)) return;
  const origin = new URL(details.url).origin;
  checkHost(origin);
});

browser.tabs.onActivated.addListener(() => refreshBadges());
browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") refreshBadges();
});

/* ------------------------------------------------------------------ */
/* Messages from content script / popup                                */
/* ------------------------------------------------------------------ */

browser.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || !msg.type) return undefined;

  if (msg.type === "contentRefs") {
    // The content script found ".git/" or ".env" references in the page source.
    if (!sender.tab || !sender.tab.url || !/^https?:/.test(sender.tab.url)) return undefined;
    const origin = new URL(sender.tab.url).origin;
    return (async () => {
      const store = await getStore();
      const entry = store[origin] || { findings: [], refs: [], lastChecked: 0 };
      const merged = new Set([...(entry.refs || []), ...msg.refs]);
      entry.refs = [...merged].slice(0, 50);
      store[origin] = entry;
      await setStore(store);
      refreshBadges();
    })();
  }

  if (msg.type === "getStatus") {
    return (async () => {
      const store = await getStore();
      if (msg.url && /^https?:/.test(msg.url)) {
        const origin = new URL(msg.url).origin;
        return { origin, entry: store[origin] || null };
      }
      return { origin: null, entry: null };
    })();
  }

  if (msg.type === "getAll") {
    return getStore();
  }

  if (msg.type === "runCheck") {
    if (!msg.url || !/^https?:/.test(msg.url)) return Promise.resolve(null);
    return checkHost(new URL(msg.url).origin, { force: true });
  }

  if (msg.type === "clearAll") {
    return browser.storage.local.remove(STORE_KEY).then(() => { refreshBadges(); });
  }

  return undefined;
});
