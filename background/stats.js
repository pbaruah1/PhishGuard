                                                            
  
                                                                              
                                                                             
                                                                          
  
                                                                             
                                                                               
                                                                              
  
                                                                         
                                                                           
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSStats = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                                
                                                                                
                         
  const RING_DAYS = 90;
  const FIELDS = ['checked', 'threats', 'privacy'];
  const CATEGORIES = ['phishing', 'fakeShop', 'wallet', 'techSupport', 'clipboard', 'clickfix', 'fakeUpdate', 'other'];

                                                                          
                                                                              
                                                                               
                               
  function dayKey(now) {
    const t = typeof now === 'number' && Number.isFinite(now) ? now : Date.now();
    return new Date(t).toISOString().slice(0, 10);
  }

  const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
  function count(v) {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

                                                                        
                                                                               
                                                                               
                                                        
  function normalize(statsDaily) {
    const seen = new Map();
    for (const b of (Array.isArray(statsDaily) ? statsDaily : [])) {
      if (!b || typeof b.d !== 'string' || !DAY_RE.test(b.d)) continue;
      let rec = seen.get(b.d);
      if (!rec) { rec = { d: b.d, checked: 0, threats: 0, privacy: 0 }; seen.set(b.d, rec); }
      for (const f of FIELDS) rec[f] += count(b[f]);
    }
    return [...seen.values()].sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : 0));
  }

                                                                                
                                                                               
                                                                     
  function bump(statsDaily, field, now) {
    const ring = normalize(statsDaily);
    if (!FIELDS.includes(field)) return ring.slice(-RING_DAYS);
    const key = dayKey(now);
    let bucket = ring.find((b) => b.d === key);
    if (!bucket) {
      bucket = { d: key, checked: 0, threats: 0, privacy: 0 };
      ring.push(bucket);
      ring.sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : 0));                            
    }
    bucket[field] += 1;
    return ring.slice(-RING_DAYS);
  }

                                                           
    
                                                                               
                                 
                                                                              
                                                                              
                                                              
                                                                                      
                                                                              
                      
                                                                         
                                                                               
                                                                               
                                                                                
                                                                             
                                                                                
                                                                            
                                          
                                                                               
                                                                        
                                        
  const BY_KIND = {
    wallet: 'wallet',
    clipboard: 'clipboard',
    techscam: 'techSupport',
                                                                                
                                                                               
                                                                                 
    clickfix: 'clickfix',
    fakeupdate: 'fakeUpdate',
    fakeUpdate: 'fakeUpdate',
                                                                            
    blocklist: 'phishing'
  };
  const BY_FLAG = {
    'seed-phrase-harvest': 'wallet',
    'clickfix': 'clickfix',
    'fake-browser-update': 'fakeUpdate',
    'delivery-fee-scam': 'fakeShop',
    'fake-alert-phone': 'techSupport',
    'credential-form-foreign-domain': 'phishing',
    'brand-impersonation-content': 'phishing',
    'brand-impersonation-visual': 'phishing'
  };
                                                                
  const REFINES = { clipboard: ['clickfix'] };
  function categoryOf(event) {
    if (!event) return 'other';
    if (typeof event === 'string') return categoryOf({ kind: event });
    const kind = typeof event.kind === 'string' ? event.kind : '';
    const verdict = (event.verdict && typeof event.verdict === 'object') ? event.verdict : event;
    const flags = Array.isArray(verdict.flags) ? verdict.flags : [];
    let flagCat = '';
    for (const f of flags) { if (BY_FLAG[f]) { flagCat = BY_FLAG[f]; break; } }
    if (BY_KIND[kind]) {
      if (flagCat && (REFINES[kind] || []).includes(flagCat)) return flagCat;
      return BY_KIND[kind];
    }
    if (flagCat) return flagCat;
    const codes = Array.isArray(verdict.reasonCodes) ? verdict.reasonCodes : [];
    if (codes.some((c) => typeof c === 'string' && c.indexOf('shop_') === 0)) return 'fakeShop';
    if (kind === 'page' || verdict.level === 'dangerous' || verdict.level === 'suspicious') return 'phishing';
    return 'other';
  }

                                       
    
                                                                         
                                                                               
                                                                         
                                                                            
                                                                 
    
                                                                                
                                                                                
                                                                             
                                                                            
                                               
  function privacyTotal(stored, statsDaily) {
    if (typeof stored === 'number' && Number.isFinite(stored) && stored >= 0) {
      return { total: Math.floor(stored), backfilled: false };
    }
    let total = 0;
    for (const b of normalize(statsDaily)) total += b.privacy;
    return { total, backfilled: true };
  }

                                                                              
                                                           
  function summarize(statsDaily, period, now) {
    const days = count(period) || 7;
    const t = typeof now === 'number' && Number.isFinite(now) ? now : Date.now();
    const from = dayKey(t - (days - 1) * 86400000);
    const to = dayKey(t);
    const out = { checked: 0, threats: 0, privacy: 0 };
    for (const b of normalize(statsDaily)) {
      if (b.d < from || b.d > to) continue;
      for (const f of FIELDS) out[f] += b[f];
    }
    return out;
  }

  return { RING_DAYS, FIELDS, CATEGORIES, dayKey, normalize, bump, categoryOf, privacyTotal, summarize };
});
