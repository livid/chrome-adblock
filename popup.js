const DEFAULT_SETTINGS = { ads: true, threats: true, cosmetic: true, cleanUrls: true };
const $ = (id) => document.getElementById(id);

let tab = null;
let host = null;

async function getState() {
  const state = await chrome.storage.local.get({ settings: DEFAULT_SETTINGS, allowlist: [], feeds: {} });
  state.settings = { ...DEFAULT_SETTINGS, ...state.settings };
  return state;
}

function ago(ts) {
  const min = Math.round((Date.now() - ts) / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  const h = Math.round(min / 60);
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} days ago`;
}

function renderLists(feeds) {
  const list = Object.values(feeds);
  const total = list.reduce((n, f) => n + (f.domains?.length || 0), 0);
  const newest = Math.max(0, ...list.map((f) => f.updated || 0));
  const failed = list.some((f) => f.error);
  const el = $("lists");
  if (!newest) {
    el.textContent = failed ? "Couldn't download lists. Built-in rules active." : "Downloading lists…";
  } else {
    el.textContent = `${total.toLocaleString()} domains listed · updated ${ago(newest)}`;
    if (failed) el.textContent += " · some lists failed to update";
  }
  el.classList.toggle("error", failed);
}

function formatBytes(n) {
  if (n < 1e6) return `${Math.round(n / 1e3)} KB`;
  if (n < 1e9) return `${(n / 1e6).toFixed(n < 1e8 ? 1 : 0)} MB`;
  return `${(n / 1e9).toFixed(n < 1e11 ? 2 : 0)} GB`;
}

function renderTotals(stats) {
  $("totalBlocked").textContent = (stats?.blocked || 0).toLocaleString();
  $("totalSaved").textContent = "≈ " + formatBytes(stats?.bytes || 0);
}

async function render() {
  const { settings, allowlist, feeds } = await getState();

  for (const input of document.querySelectorAll("[data-setting]")) {
    input.checked = settings[input.dataset.setting];
  }

  const siteToggle = $("siteToggle");
  if (host) {
    const paused = allowlist.includes(host);
    $("host").textContent = host;
    siteToggle.checked = !paused;
    $("status").textContent = paused ? "Ad blocking paused on this site" : "Protection is on";
    $("status").classList.toggle("paused", paused);
  } else {
    $("host").textContent = "This page";
    $("status").textContent = "Shield doesn't run on browser pages";
    siteToggle.checked = false;
    siteToggle.disabled = true;
  }

  renderLists(feeds);
}

async function init() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    const url = new URL(tab.url);
    if (/^https?:$/.test(url.protocol)) host = url.hostname.replace(/^www\./, "");
  } catch {}

  await render();

  // Totals are counted from per-match events, which Chrome only gives unpacked installs.
  if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
    renderTotals((await chrome.storage.local.get("stats")).stats);
  } else {
    $("totals").hidden = true;
  }

  if (tab && host) {
    const text = await chrome.action.getBadgeText({ tabId: tab.id }).catch(() => "");
    $("count").textContent = /^\d+$/.test(text) ? Number(text).toLocaleString() : "0";
  }

  $("siteToggle").addEventListener("change", async (e) => {
    const { allowlist } = await getState();
    const next = allowlist.filter((d) => d !== host);
    if (!e.target.checked) next.push(host);
    await chrome.storage.local.set({ allowlist: next });
    await render();
    // Give the background a moment to swap rules, then reload so the change shows.
    setTimeout(() => chrome.tabs.reload(tab.id), 300);
  });

  for (const input of document.querySelectorAll("[data-setting]")) {
    input.addEventListener("change", async () => {
      const { settings } = await getState();
      settings[input.dataset.setting] = input.checked;
      await chrome.storage.local.set({ settings });
    });
  }

  $("update").addEventListener("click", async () => {
    const btn = $("update");
    btn.disabled = true;
    btn.textContent = "Updating…";
    await chrome.runtime.sendMessage({ type: "update-feeds" }).catch(() => {});
    btn.disabled = false;
    btn.textContent = "Update lists";
    await render();
  });

  chrome.storage.onChanged.addListener((changes) => {
    if (changes.feeds) renderLists(changes.feeds.newValue || {});
    if (changes.stats) renderTotals(changes.stats.newValue);
  });
}

init();
