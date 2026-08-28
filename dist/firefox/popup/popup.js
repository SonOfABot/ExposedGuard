"use strict";

const $ = id => document.getElementById(id);

/* Safe DOM helper: textContent only, never innerHTML (AMO policy). */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(state, text) {
  const node = $("status");
  node.className = "pill " + state;
  node.textContent = text;
}

function renderFindings(entry) {
  const ul = $("findings");
  ul.replaceChildren();
  const refsUl = $("refs");
  refsUl.replaceChildren();
  $("refs-wrap").hidden = true;

  const findings = (entry && entry.findings) || [];
  const refs = (entry && entry.refs) || [];

  if (findings.length === 0) {
    setStatus(refs.length ? "pill-warn" : "pill-clean",
              refs.length ? "references only" : "clean");
    if (entry && entry.lastChecked) {
      const li = el("li");
      li.append(
        el("span", "path", "No exposed .git / .env"),
        el("span", "sev", "checked " + new Date(entry.lastChecked).toLocaleTimeString())
      );
      ul.appendChild(li);
    }
  } else {
    const hasCritical = findings.some(f => f.severity === "critical");
    setStatus("pill-bad", hasCritical ? "CRITICAL exposure" : `${findings.length} exposed`);
    for (const f of findings) {
      const li = el("li", "sev-" + f.severity);
      li.append(
        el("span", "path", f.path),
        el("span", "sev", f.severity),
        el("div", "preview", f.preview || "")
      );
      li.title = f.url;
      ul.appendChild(li);
    }
  }

  if (refs.length) {
    $("refs-wrap").hidden = false;
    for (const r of refs) {
      refsUl.appendChild(el("li", "", "- " + r));
    }
  }
}

async function loadHistory(currentOrigin) {
  const store = await browser.runtime.sendMessage({ type: "getAll" });
  const ul = $("history-list");
  ul.replaceChildren();
  const entries = Object.entries(store || {})
    .filter(([, e]) => (e.findings && e.findings.length) || (e.refs && e.refs.length))
    .sort((a, b) => (b[1].lastChecked || 0) - (a[1].lastChecked || 0));

  if (entries.length === 0) {
    ul.appendChild(el("li", "empty", "Nothing found yet."));
    return;
  }
  for (const [origin, e] of entries) {
    const n = (e.findings || []).length;
    const host = new URL(origin).host;
    const li = el("li");
    li.append(
      el("span", "h-host", host + (origin === currentOrigin ? " (this tab)" : "")),
      el("span", "h-count", n ? n + " exposed" : "refs only")
    );
    ul.appendChild(li);
  }
}

async function refresh(tab) {
  if (!tab || !/^https?:/.test(tab.url || "")) {
    $("host").textContent = "Not an http(s) page";
    setStatus("pill-idle", "n/a");
    $("findings").replaceChildren();
    await loadHistory(null);
    return;
  }
  const origin = new URL(tab.url).origin;
  $("host").textContent = new URL(tab.url).host;
  const res = await browser.runtime.sendMessage({ type: "getStatus", url: tab.url });
  renderFindings(res && res.entry);
  await loadHistory(origin);
}

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  await refresh(tab);

  $("recheck").addEventListener("click", async () => {
    if (!tab || !/^https?:/.test(tab.url || "")) return;
    const btn = $("recheck");
    btn.disabled = true;
    btn.textContent = "Checking...";
    const entry = await browser.runtime.sendMessage({ type: "runCheck", url: tab.url });
    renderFindings(entry);
    await loadHistory(new URL(tab.url).origin);
    btn.disabled = false;
    btn.textContent = "Re-check this site";
  });

  $("clear").addEventListener("click", async () => {
    await browser.runtime.sendMessage({ type: "clearAll" });
    await refresh(tab);
  });
});
