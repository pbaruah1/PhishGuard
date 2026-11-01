(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                               
                                                                        
                                                                              
                                                                                                                           
    
                                                                            
                                                                            
                                                                            
                                                                 
  const CAP = 500;                                                                          
  const STALE_MS = 60 * 24 * 3600 * 1000;                                              
  const SESSION_GAP_MS = 30 * 60 * 1000;                                            
  const MIN_VISITS = 3;                                                                
  const RECENT_MS = 30 * 24 * 3600 * 1000;                                              

                                                                     
  function recordVisit(map, domain, now) {
    if (!domain) return map || {};
    const m = Object.assign({}, map);
    const cur = m[domain];
    if (cur && now - cur.ts < SESSION_GAP_MS) {
      m[domain] = { n: cur.n, ts: now };                                                 
    } else {
      m[domain] = { n: Math.min(((cur && cur.n) || 0) + 1, 999), ts: now };
    }
    for (const k of Object.keys(m)) if (now - m[k].ts > STALE_MS) delete m[k];
    const keys = Object.keys(m);
    if (keys.length > CAP) {
      keys.sort((a, b) => m[a].ts - m[b].ts);
      for (const k of keys.slice(0, keys.length - CAP)) delete m[k];
    }
    return m;
  }

  function isEngaged(map, domain, now) {
    const e = map && map[domain];
    return !!(e && e.n >= MIN_VISITS && now - e.ts <= RECENT_MS);
  }

  return { engagement: { recordVisit, isEngaged, CAP, MIN_VISITS, SESSION_GAP_MS } };
});
