// Shield service worker: keeps blocking rules in sync with settings and remote blocklists.

const FEEDS = {
  ads: {
    kind: "ads",
    url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext",
  },
  malware: {
    kind: "threats",
    url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt",
  },
  phishing: {
    kind: "threats",
    url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
  },
};

const MAX_DOMAINS_PER_FEED = 30000;
const UPDATE_ALARM = "update-feeds";
const UPDATE_PERIOD_MIN = 12 * 60;

// Built-in threats (browser cryptominers) so protection works before the first feed download.
const THREAT_SEED = [
  "coinhive.com", "coin-hive.com", "authedmine.com", "crypto-loot.com", "cryptoloot.pro",
  "coinimp.com", "jsecoin.com", "webminepool.com", "minero.cc", "monerominer.rocks",
  "coinerra.com", "ppoi.org", "minr.pw", "webmine.cz", "cryptonoter.com", "mineralt.io",
];

// Never block these via a threat feed, even if a feed lists them: a bad entry here
// would take out a large part of the web. Subdomains of the first group are protected too.
const NEVER_BLOCK_TREE = [
  "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com",
  "microsoft.com", "live.com", "office.com", "windows.net", "apple.com", "icloud.com",
  "amazon.com", "amazonaws.com", "cloudfront.net", "github.com", "githubusercontent.com",
  "gitlab.com", "dropbox.com", "dropboxusercontent.com", "discord.com", "discordapp.com",
  "cloudflare.com", "wikipedia.org", "abuse.ch",
];
const NEVER_BLOCK_EXACT = [
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
  "vercel.app", "netlify.app", "weebly.com", "wixsite.com", "blogspot.com", "wordpress.com",
  "translate.goog", "herokuapp.com", "azurewebsites.net", "r2.dev",
];

const RULE = { THREAT_PAGE: 1, THREAT_REQUEST: 2, AD_FEED: 3, ALLOWLIST: 4 };
// Static ad rules use priority 1. A paused site beats ad rules but never threat rules.
const PRIORITY = { ADS: 1, ALLOWLIST: 20, THREAT: 30, PROCEED: 40 };

const DEFAULT_SETTINGS = { ads: true, threats: true, cosmetic: true, cleanUrls: true };
// Sites left alone out of the box. They appear as "paused" in the popup and can be switched back on.
const DEFAULT_PAUSED_SITES = ["youtube.com", "youtube-nocookie.com"]; // the second serves embedded players
const GENERIC_COSMETIC_ID = "generic-cosmetic";
const WEB_PAGES = ["http://*/*", "https://*/*"];
const WARNING_PAGE = chrome.runtime.getURL("blocked.html");

const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

async function getState() {
  const state = await chrome.storage.local.get({ settings: DEFAULT_SETTINGS, allowlist: [], feeds: {} });
  state.settings = { ...DEFAULT_SETTINGS, ...state.settings };
  return state;
}

function parseDomains(text) {
  const out = new Set();
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0].trim().toLowerCase();
    if (!line || line.startsWith("!")) continue;
    const host = line.split(/\s+/).pop(); // handles "0.0.0.0 example.com" hosts format too
    if (DOMAIN_RE.test(host) || IPV4_RE.test(host)) out.add(host);
    if (out.size >= MAX_DOMAINS_PER_FEED) break;
  }
  return [...out];
}

function isProtected(domain) {
  return (
    NEVER_BLOCK_EXACT.includes(domain) ||
    NEVER_BLOCK_TREE.some((d) => domain === d || domain.endsWith("." + d))
  );
}

function threatDomains(feeds) {
  const all = new Set(THREAT_SEED);
  for (const [name, feed] of Object.entries(FEEDS)) {
    if (feed.kind !== "threats") continue;
    for (const d of feeds[name]?.domains ?? []) if (!isProtected(d)) all.add(d);
  }
  return [...all];
}

function buildRules({ settings, allowlist, feeds }, { includeIps = true } = {}) {
  const keep = (list) => (includeIps ? list : list.filter((d) => !IPV4_RE.test(d)));
  const rules = [];

  if (settings.threats) {
    const domains = keep(threatDomains(feeds));
    // Navigating to a dangerous site shows a warning page instead.
    rules.push({
      id: RULE.THREAT_PAGE,
      priority: PRIORITY.THREAT,
      action: { type: "redirect", redirect: { regexSubstitution: WARNING_PAGE + "#\\0" } },
      condition: { regexFilter: "^https?://.+", requestDomains: domains, resourceTypes: ["main_frame"] },
    });
    // Anything else loaded from a dangerous host (scripts, frames, downloads...) is dropped.
    rules.push({
      id: RULE.THREAT_REQUEST,
      priority: PRIORITY.THREAT,
      action: { type: "block" },
      condition: { requestDomains: domains },
    });
  }

  const adDomains = keep(feeds.ads?.domains ?? []);
  if (settings.ads && adDomains.length) {
    rules.push({
      id: RULE.AD_FEED,
      priority: PRIORITY.ADS,
      action: { type: "block" },
      condition: { requestDomains: adDomains },
    });
  }

  if (allowlist.length) {
    rules.push({
      id: RULE.ALLOWLIST,
      priority: PRIORITY.ALLOWLIST,
      action: { type: "allowAllRequests" },
      // sub_frame: a paused site is also left alone when embedded in another page (e.g. video players).
      condition: { requestDomains: allowlist, resourceTypes: ["main_frame", "sub_frame"] },
    });
  }
  return rules;
}

// Rule updates are serialized so overlapping triggers can't interleave.
let queue = Promise.resolve();
function applyRules() {
  queue = queue.then(doApplyRules).catch((e) => console.error("Shield: applying rules failed", e));
  return queue;
}

async function doApplyRules() {
  const state = await getState();
  const removeRuleIds = Object.values(RULE);
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: buildRules(state) });
  } catch (e) {
    // If Chrome rejects an entry, retry with hostnames only rather than losing protection.
    console.warn("Shield: retrying without IP entries:", e.message);
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules: buildRules(state, { includeIps: false }),
    });
  }
  // Static rulesets are compiled from Brave's default filter lists by tools/build-rules.mjs.
  const { ads, threats, cleanUrls } = state.settings;
  const wanted = { ads, privacy: ads, annoyances: ads, threats, "clean-urls": cleanUrls };
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds: Object.keys(wanted).filter((id) => wanted[id]),
    disableRulesetIds: Object.keys(wanted).filter((id) => !wanted[id]),
  });

  await syncGenericCosmetics(state);
}

const loadJson = (file) => fetch(chrome.runtime.getURL(file)).then((r) => r.json());
const isPaused = (host, allowlist) => allowlist.some((d) => host === d || host.endsWith("." + d));

// Generic element hiding is a registered stylesheet, so it applies before the page
// paints and without waking this worker. Paused sites and sites the lists exempt are excluded.
async function syncGenericCosmetics({ settings, allowlist }) {
  await chrome.scripting.unregisterContentScripts({ ids: [GENERIC_COSMETIC_ID] }).catch(() => {});
  if (!settings.ads || !settings.cosmetic) return;

  const patterns = (hosts) =>
    hosts.flatMap((h) => (IPV4_RE.test(h) ? [`*://${h}/*`] : [`*://${h}/*`, `*://*.${h}/*`]));
  const script = { id: GENERIC_COSMETIC_ID, css: ["cosmetic/generic.css"], matches: WEB_PAGES, runAt: "document_start" };
  const exempt = await loadJson("cosmetic/no-generic.json").catch(() => []);
  try {
    await chrome.scripting.registerContentScripts([{ ...script, excludeMatches: patterns([...allowlist, ...exempt]) }]);
  } catch (e) {
    console.warn("Shield: registering without list exemptions:", e.message);
    await chrome.scripting.registerContentScripts([{ ...script, excludeMatches: patterns(allowlist) }]);
  }
}

// Site-specific element hiding is looked up per navigation.
let specificCosmetics;
chrome.webNavigation.onCommitted.addListener(
  async ({ tabId, frameId, url }) => {
    if (frameId !== 0) return;
    const host = new URL(url).hostname;
    const { settings, allowlist } = await chrome.storage.local.get({ settings: DEFAULT_SETTINGS, allowlist: [] });
    if (settings.ads === false || settings.cosmetic === false || isPaused(host, allowlist)) return;

    specificCosmetics ??= loadJson("cosmetic/specific.json").catch(() => ({}));
    const table = await specificCosmetics;
    const selectors = [];
    // Check the hostname and each parent domain: a.b.example.com, b.example.com, example.com.
    for (let h = host; h.includes("."); h = h.slice(h.indexOf(".") + 1)) {
      if (Object.hasOwn(table, h)) selectors.push(...table[h]);
    }
    if (!selectors.length) return;
    const css = selectors.map((s) => `${s}{display:none!important}`).join("\n");
    chrome.scripting.insertCSS({ target: { tabId }, css, origin: "USER" }).catch(() => {});
  },
  { url: [{ schemes: ["http", "https"] }] }
);

async function updateFeeds() {
  const { feeds } = await getState();
  await Promise.all(
    Object.entries(FEEDS).map(async ([name, feed]) => {
      const prev = feeds[name] ?? { domains: [], updated: 0 };
      try {
        const res = await fetch(feed.url, { cache: "no-store" });
        if (!res.ok) throw new Error("HTTP " + res.status);
        const domains = parseDomains(await res.text());
        if (!domains.length) throw new Error("list was empty");
        feeds[name] = { domains, updated: Date.now(), error: null };
      } catch (e) {
        feeds[name] = { ...prev, error: String(e.message || e) }; // keep the last good copy
      }
    })
  );
  await chrome.storage.local.set({ feeds });
  await applyRules();
}

// Adds each default paused site once, so switching one back on in the popup sticks.
async function seedPausedSites() {
  const { allowlist, seededPaused } = await chrome.storage.local.get({ allowlist: [], seededPaused: [] });
  const fresh = DEFAULT_PAUSED_SITES.filter((d) => !seededPaused.includes(d));
  if (!fresh.length) return;
  await chrome.storage.local.set({
    allowlist: [...new Set([...allowlist, ...fresh])],
    seededPaused: [...seededPaused, ...fresh],
  });
}

async function ensureAlarm() {
  if (!(await chrome.alarms.get(UPDATE_ALARM))) {
    chrome.alarms.create(UPDATE_ALARM, { periodInMinutes: UPDATE_PERIOD_MIN });
  }
}

async function allowForSession(url) {
  const host = new URL(url).hostname;
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  const id = existing.reduce((max, r) => Math.max(max, r.id), 1000) + 1;
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [
      {
        id,
        priority: PRIORITY.PROCEED,
        action: { type: "allow" },
        condition: {
          requestDomains: [host],
          resourceTypes: [
            "main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object",
            "xmlhttprequest", "ping", "media", "websocket", "webtransport", "other",
          ],
        },
      },
    ],
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.declarativeNetRequest.setExtensionActionOptions({ displayActionCountAsBadgeText: true });
  chrome.action.setBadgeBackgroundColor({ color: "#2f6fed" });
  await ensureAlarm();
  await seedPausedSites();
  await applyRules(); // built-in protection right away
  await updateFeeds(); // then the full lists
});

chrome.runtime.onStartup.addListener(async () => {
  await ensureAlarm();
  const { feeds } = await getState();
  const newest = Math.max(0, ...Object.values(feeds).map((f) => f.updated || 0));
  if (Date.now() - newest > UPDATE_PERIOD_MIN * 60_000) await updateFeeds();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === UPDATE_ALARM) updateFeeds();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.settings || changes.allowlist)) applyRules();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "update-feeds") {
    updateFeeds().then(() => sendResponse({ ok: true }), (e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg?.type === "proceed") {
    // Only the warning page itself, shown as a top-level tab, may lift a block.
    const fromWarning = sender.url?.startsWith(WARNING_PAGE) && sender.frameId === 0;
    if (!fromWarning || !/^https?:\/\//.test(msg.url || "")) {
      sendResponse({ ok: false });
      return;
    }
    allowForSession(msg.url).then(() => sendResponse({ ok: true }), () => sendResponse({ ok: false }));
    return true;
  }
});
