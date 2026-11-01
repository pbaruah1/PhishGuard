                                                                                 
  
                                                                             
                                                                              
                                                                            
                                                                             
                                                                             
                                                                    
                                                                        
  
                                                                              
                                                                           
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSUpdate = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                            
                                                                            
                                                                           
                                 
  const MAX_DEFER_MS = 30 * 60 * 1000;
                                                                           
                                                                           
  const RECHECK_MINUTES = 1;

                                                                            
                                                                           
                                                                               
  function openPageCount(contexts) {
    if (!Array.isArray(contexts)) return 0;
    let n = 0;
    for (const c of contexts) {
      if (!c) continue;
      if (typeof c.contextType === 'string') { if (c.contextType !== 'BACKGROUND') n++; }
      else n++;
    }
    return n;
  }

     
                                                                       
                                                                                 
                                                                        
                                                                 
                              
     
  function decide(state) {
    const s = state || {};
    const now = typeof s.now === 'number' ? s.now : Date.now();
    const since = typeof s.pendingSince === 'number' ? s.pendingSince : now;
    if (now - since >= MAX_DEFER_MS) return { apply: true, reason: 'max-defer' };
    const pages = openPageCount(s.contexts);
    if (pages > 0) return { apply: false, reason: 'pages-open' };
    if ((s.busy | 0) > 0) return { apply: false, reason: 'busy' };
    return { apply: true, reason: 'idle' };
  }

                                                                            
                                                                              
                                                                           
                                                       
  function parseVersion(v) {
    if (typeof v !== 'string' || !/^\d+(\.\d+){0,3}$/.test(v)) return null;
    return v.split('.').map(Number);
  }
  function versionLessThan(a, b) {
    const x = parseVersion(a), y = parseVersion(b);
    if (!x || !y) return false;
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const d = (x[i] || 0) - (y[i] || 0);
      if (d !== 0) return d < 0;
    }
    return false;
  }

                                                   
                                                                              
                                                                              
                                                                        
                                                             
                                                                           
                                                                      
  function getAlarm(alarms, name) {
    return new Promise((resolve) => {
      try {
                                                                            
                                                                         
                                          
        const r = alarms.get(name);
        if (r && typeof r.then === 'function') { r.then(resolve, () => resolve(undefined)); return; }
        alarms.get(name, resolve);
      } catch (_) { resolve(undefined); }
    });
  }
  async function ensureAlarm(alarms, name, periodInMinutes) {
    const existing = await getAlarm(alarms, name);
    if (existing && existing.periodInMinutes === periodInMinutes) return 'kept';
    alarms.create(name, { periodInMinutes });
    return 'created';
  }

                                                                              
                                                                           
                                                                           
                       
  const FEED_TOPUP_MS = 12 * 60 * 60 * 1000;
  function shouldTopUpFeed(lastAttemptAt, now) {
    const t = typeof now === 'number' ? now : Date.now();
    const a = typeof lastAttemptAt === 'number' ? lastAttemptAt : 0;
    return t - a > FEED_TOPUP_MS;
  }

                                                                           
                                                                          
                                                                            
                                                                             
  function singleFlight(fn) {
    let inflight = null;
    return function () {
      if (inflight) return inflight;
      const p = Promise.resolve().then(() => fn());
      inflight = p;
      const clear = () => { if (inflight === p) inflight = null; };
      p.then(clear, clear);
      return p;
    };
  }

  return { singleFlight, MAX_DEFER_MS, RECHECK_MINUTES, FEED_TOPUP_MS, openPageCount, decide, versionLessThan, ensureAlarm, shouldTopUpFeed };
});
