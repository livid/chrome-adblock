// The blocked address arrives in the URL fragment. Treat it as untrusted text.
let target = null;
try {
  const url = new URL(location.hash.slice(1));
  if (url.protocol === "http:" || url.protocol === "https:") target = url;
} catch {}

const proceed = document.getElementById("proceed");
document.getElementById("host").textContent = target ? target.hostname : "Unknown address";

// No bypass when embedded in another page (clickjacking) or without a valid address.
if (!target || window.top !== window) proceed.hidden = true;

document.getElementById("back").addEventListener("click", async () => {
  if (history.length > 1) {
    history.back();
  } else {
    const tab = await chrome.tabs.getCurrent();
    if (tab) chrome.tabs.remove(tab.id);
  }
});

proceed.addEventListener("click", async () => {
  proceed.disabled = true;
  const res = await chrome.runtime.sendMessage({ type: "proceed", url: target.href }).catch(() => null);
  if (res?.ok) location.replace(target.href);
  else proceed.disabled = false;
});
