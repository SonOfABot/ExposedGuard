"use strict";

/*
 * ExposedGuard - content script
 * Scans the rendered page for references to .git / .env
 * (in markup, attributes, inline scripts, comments) and reports
 * them to the background worker. These are weaker signals than a
 * directly fetchable file, so they are shown as "references".
 */

(function () {
  const PATTERNS = [
    { re: /["'`(\s=]\/?\.git(?:\/|["'`)\s])/i, label: ".git path" },
    { re: /["'`(\s=]\/?\.svn\//i, label: ".svn path" },
    { re: /["'`(\s=]\/?\.hg\//i, label: ".hg path" },
    { re: /["'`(\s=][^"'`)\s]*\.env(?:\.local|\.production|\.development|\.staging|\.backup|\.old)?["'`)\s]/i, label: ".env file reference" },
    { re: /wp-config\.php/i, label: "wp-config reference" },
    { re: /BEGIN [A-Z ]*PRIVATE KEY/, label: "private key material" },
    { re: /DB_PASSWORD|DB_CONNECTION|DATABASE_URL/i, label: "database config reference" },
    { re: /aws_secret_access_key/i, label: "AWS credential reference" },
    { re: /repositoryformatversion/i, label: "git config content" },
    { re: /\[branch "[^"]+"\]/i, label: "git config content" },
    { re: /refs\/heads\/[A-Za-z0-9_\-\/.]+/i, label: "git ref" }
  ];

  function scan() {
    try {
      const html = document.documentElement.innerHTML || "";
      const found = new Set();
      for (const p of PATTERNS) {
        if (p.re.test(html)) found.add(p.label);
      }
      // Also scan attributes (src, href, data-*) for hidden paths.
      const attrs = document.querySelectorAll("[src], [href], [data-src]");
      for (const el of attrs) {
        for (const a of ["src", "href", "data-src"]) {
          const v = el.getAttribute(a);
          if (v && /(\.git\/|\.env\b)/i.test(v)) found.add("attribute path: " + v.slice(0, 80));
        }
      }
      if (found.size > 0) {
        browser.runtime.sendMessage({ type: "contentRefs", refs: [...found] });
      }
    } catch (e) {
      /* never break the host page */
    }
  }

  scan();
})();
