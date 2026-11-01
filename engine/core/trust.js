                                                           
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';
  function pauseUntil(choice, now) {
    const t = typeof now === 'number' ? now : Date.now();
    if (choice === 'always') return null;
                                                                               
                                                                             
                                                                           
    if (choice === '1d') return t + 86400000;
    return t + 3600000;                             
  }
  function isPaused(pausedSites, domain, now) {
    const t = typeof now === 'number' ? now : Date.now();
    const until = pausedSites && pausedSites[domain];
    return typeof until === 'number' && until > t;
  }
  function prunePaused(pausedSites, now) {
    const t = typeof now === 'number' ? now : Date.now(); const out = {};
    for (const k in (pausedSites || {})) if (typeof pausedSites[k] === 'number' && pausedSites[k] > t) out[k] = pausedSites[k];
    return out;
  }
  return { pauseUntil, isPaused, prunePaused };
});
