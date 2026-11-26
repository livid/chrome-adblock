// Stops Ad-Shield, an ad-recovery service, before it runs. Its inline bootstrap hooks
// fetch, XHR and script errors so that every ad request Shield blocks is queued, and its
// loader (served from rotating domains) then re-fetches those ads through its own proxies
// and strips Shield's element-hiding styles from the page. Neither script can be blocked
// by URL, so both are caught as the parser inserts them: a script that is detached and
// no longer JavaScript when the parser comes to run it never executes.
(() => {
  const isAdShield = (script) =>
    script.dataset.sdk?.startsWith("wp-ls/") || // the loader
    (!script.src && /__as_ready_resolve|_as_prehooked/.test(script.text)); // the bootstrap

  const check = (node) => {
    if (node.nodeName !== "SCRIPT" || !isAdShield(node)) return;
    node.type = "text/plain";
    node.remove();
  };

  new MutationObserver((records) => {
    for (const record of records) {
      // An inline script's text can arrive after the element itself.
      check(record.target);
      record.addedNodes.forEach(check);
    }
  }).observe(document, { childList: true, subtree: true });
})();
