"use strict";

const $ = id => document.getElementById(id);

function setStatus(state, text) {
  const el = $("status");
  el.className = "pill " + state;
  el.textContent = text;
}

function renderFindings(entry) {
  const ul = $("findings");
  ul.innerHTML = "";
  const refsUl = $("refs");
  refsUl.innerHTML = "";
  $("refs-wrap").hidden = true;

  const findings = (entry && entry.findings) || [];
  const refs = (entry && entry.refs) || [];

  if (findings.length === 0) {
    setStatus(refs.length ? "pill-warn" : "pill-clean",
              refs.length ? "references only" : "clean");
    if (entry && entry.lastChecked) {
      const li = document.createElement("li");
      li.className = "git";
      li.innerHTML = `<span class="path">No exposed .git / .env</span>
        <span class="sev">checked ${new Date(entry.lastChecked).toLocaleTimeString()}</span>`;
      ul.appendChild(li);
    }
  } else {
    const hasCritical = findings.some(f => f.severity === "critical");
    setStatus("pill-bad", hasCritical ? "CRITICAL exposure" : `${findings.length} exposed`);
    for (const f of findings) {
      const li = document.createElement("li");
      li.className = "sev-" + f.severity;
      const preview = (f.preview || "").replace(/[&<>]/g,
        c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
      li.innerHTML = `<span class="path">${f.path}</span>
        <span class="sev">${f.severity}</span>
        <div class="preview">${preview}</div>`;
      li.title = f.url;
      ul.appendChild(li);
    }
  }

  if (refs.length) {
    $("refs-wrap").hidden = false;
    for (const r of refs) {
      const li = document.createElement("li");
      li.textContent = "- " + r;
      refsUl.appendChild(li);
    }
  }
}

async function loadHistory(currentOrigin) {
  const store = await browser.runtime.sendMessage({ type: "getAll" });
  const ul = $("history-list");
  ul.innerHTML = "";
  const entries = Object.entries(store || {})
    .filter(([, e]) => (e.findings && e.findings.length) || (e.refs && e.refs.length))
    .sort((a, b) => (b[1].lastChecked || 0) - (a[1].lastChecked || 0));

  if (entries.length === 0) {
    ul.innerHTML = `<li class="empty">Nothing found yet.</li>`;
    return;
  }
  for (const [origin, e] of entries) {
    const li = document.createElement("li");
    const n = (e.findings || []).length;
    const host = new URL(origin).host;
    li.innerHTML = `<span class="h-host">${host}${origin === currentOrigin ? " (this tab)" : ""}</span>
      <span class="h-count">${n ? n + " exposed" : "refs only"}</span>`;
    ul.appendChild(li);
  }
}

async function refresh(tab) {
  if (!tab || !/^https?:/.test(tab.url || "")) {
    $("host").textContent = "Not an http(s) page";
    setStatus("pill-idle", "n/a");
    $("findings").innerHTML = "";
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
