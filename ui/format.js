               
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSFormat = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';
                                                                        
                                                                             
                                                                           
                                                      
  function relTimeIn(loc, ts, d) {
    const rtf = new Intl.RelativeTimeFormat(loc, { numeric: 'auto' });
    if (d < 60000) return rtf.format(0, 'second');
    if (d < 3600000) return rtf.format(-Math.round(d / 60000), 'minute');
    if (d < 86400000) return rtf.format(-Math.round(d / 3600000), 'hour');
    if (d < 2 * 86400000) return rtf.format(-1, 'day');
    const dt = new Date(ts);
    if (d < 7 * 86400000) return new Intl.DateTimeFormat(loc, { weekday: 'short' }).format(dt);
    return new Intl.DateTimeFormat(loc, { day: 'numeric', month: 'short' }).format(dt);
  }
  function relTime(ts, now, locale) {
    const t = typeof now === 'number' ? now : Date.now(); const d = Math.max(0, t - ts);
    try { return relTimeIn(locale || 'en', ts, d); } catch (_) { return relTimeIn('en', ts, d); }
  }
                                                                               
                                                                            
                                                                              
                                                                
  const LABELS = { page: 'Page', brand: 'Brand', wallet: 'Wallet', clipboard: 'Clipboard', techscam: 'Scare page', link: 'Link', shop: 'Shop', message: 'Message', blocklist: 'Blocked site' };
  function detectorLabel(kind) { return LABELS[kind] || 'Page'; }
  function levelText(level) {
    return level === 'dangerous' ? 'High-risk activity detected' : level === 'suspicious' ? 'Review before proceeding' : level === 'safe' ? 'No major warning signals found' : "Can't check this page";
  }
  return { relTime, detectorLabel, levelText };
});
