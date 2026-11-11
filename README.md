# Shield – Ad & Threat Blocker

A Manifest V3 Chrome extension that blocks ads, trackers, cryptominers, and known malware and phishing sites. The rulesets are compiled from the filter lists Brave Shields enables by default; see [NOTICE.md](NOTICE.md) for sources and licenses.

Requires Chrome 121 or later. There is no build step: the compiled rules are committed, so the repo folder is the extension.

## Install with Claude Code

Paste this prompt into Claude Code on the computer you want to install on:

```text
Install the Shield Chrome extension from https://github.com/livid/chrome-adblock on this computer.

1. If ~/chrome-adblock does not exist, clone the repo there. If it exists, run `git pull --ff-only` in it instead. Chrome loads the extension from this folder every time it starts, so it must stay in place.
2. Check that ~/chrome-adblock/manifest.json exists and tell me the version in it.
3. Copy the absolute path of that folder to my clipboard.
4. Open chrome://extensions in Google Chrome. If you cannot open it, ask me to type it into the address bar.
5. Chrome does not allow unpacked extensions to be installed from the command line, so do not try launch flags, policies, or registry edits. Tell me to do these steps myself:
   - turn on "Developer mode" (top right)
   - click "Load unpacked" and paste the folder path from my clipboard
   - if Shield was already installed, click its reload icon instead
6. Wait for me to confirm, then remind me to pin Shield from the toolbar's puzzle-piece menu.

Do not run the build script or change any files in the repo.
```

## Install by hand

1. `git clone https://github.com/livid/chrome-adblock`
2. Open `chrome://extensions` and turn on **Developer mode**.
3. Click **Load unpacked** and pick the cloned folder.

To update, run `git pull` in the folder and click the reload icon on the Shield card in `chrome://extensions`.

## Rebuilding the rules

`node tools/build-rules.mjs` downloads the current filter lists and regenerates `rules/` and `cosmetic/`. This is only needed to refresh the bundled lists.
