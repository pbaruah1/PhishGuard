(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                            
                                                                             
                                                                             
                                                                               
                                                                             
                                                                            
                                                                               
  const BROWSER_RE = /\b(google\s+chrome|chrome|mozilla\s+firefox|firefox|microsoft\s+edge|opera|brave|safari|your\s+browser)\b/i;
  const UPDATE_RE = /\b(update\s+(is\s+)?(required|available|needed|now)|out[\s-]?of[\s-]?date|outdated\s+(browser|version)|critical\s+(browser\s+|security\s+)?update|update\s+your\s+browser|browser\s+update)\b/i;

                                                                           
  const VENDOR_DOMAINS = [
    'google.com', 'chrome.com', 'mozilla.org', 'firefox.com', 'getfirefox.com',
    'microsoft.com', 'microsoftedge.com', 'apple.com', 'opera.com', 'brave.com',
    'browser-update.org'
  ];

  function isVendorHost(host) {
    const h = String(host || '').toLowerCase();
    return VENDOR_DOMAINS.some((d) => h === d || h.endsWith('.' + d));
  }

                                                                              
                                                                           
  function scoreFakeUpdate(input) {
    const s = input || {};
    const text = String(s.text || '');
    const reasons = [];
    const flags = [];
    if (!(BROWSER_RE.test(text) && UPDATE_RE.test(text))) return { level: 'none', reasons, flags };
    const anchorHosts = Array.isArray(s.updateAnchorHosts) ? s.updateAnchorHosts : [];
    const nonVendor = anchorHosts.filter((h) => h && !isVendorHost(h));
    const hasBadDownload = nonVendor.length > 0 || s.hasBlobDownload === true;
    if (hasBadDownload) {
      flags.push('fake-browser-update');
      reasons.push({ code: 'fakeUpdatePrompt', kind: 'page' });
      return { level: 'dangerous', reasons, flags };
    }
                                                                                
    return { level: 'none', reasons, flags };
  }

  return { scoreFakeUpdate, __fakeUpdateVendors: VENDOR_DOMAINS };
});
