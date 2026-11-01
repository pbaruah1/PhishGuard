                                                                            
  
                                                                         
                                                                   
                                                                           
  
                                                  
                                                                             
                                                                             
                                                                     
                                                                        
                                                                           
                                                                             
                                                                   
                                                                           
                                                                             
                                                                         
                                                                        
                                                                      
                                                                              
                                                                           
                                                                            
                                                                           
                                                                       
                                                                        
                                                                            
                                                                            
                                                                            
                                                                            
                                                                         
                                                                
  
                                                                            
                        
(function (root, factory) {
  const mod = factory(typeof require === 'function' ? require('../core/constants') : root.PhishGuard);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSDnr = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C) {
  'use strict';

  const BLOCK_BASE = 100000;
  const REDIRECT_BASE = 200000;
  const ALLOW_BASE = 300000;
  const HOT_BASE = 400000;                                                                    
  const PATH_BASE = 500000;                                                          
  const RANGE = 100000;
  const CHUNK = 2500;                                                                                                
  const MAX_ALLOW = 1000;                                                              
  const MAX_PATH_RULES = 300;                                                                  
                                                                             
                                                                           
                                                                     
  const HOST_LABELS_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

  function escapeRegex(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

                                                                           
                                                                           
  function domainOfFilter(urlFilter) {
    const m = /^\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^$/i.exec(String(urlFilter || '').trim());
    if (!m) return null;
    return m[1].toLowerCase();
  }

  function inRange(id, base) { return typeof id === 'number' && id >= base && id < base + RANGE; }

  function buildBlockRules(filters) {
    return (filters || []).map((f, i) => ({
      id: BLOCK_BASE + i, priority: 1, action: { type: 'block' },
      condition: { urlFilter: String(f), resourceTypes: ['main_frame', 'sub_frame'] }
    }));
  }

                                                                         
                                                           
                                                                             
  function buildRedirectRules(domains, targetUrl, base) {
    const b = typeof base === 'number' ? base : REDIRECT_BASE;
    const uniq = [...new Set([...(domains || [])].filter(Boolean).map((d) => String(d).toLowerCase()))];
    const rules = [];
    for (let i = 0; i < uniq.length; i += CHUNK) {
      rules.push({
        id: b + rules.length, priority: 2,
        action: { type: 'redirect', redirect: { regexSubstitution: targetUrl + '#\\0' } },
        condition: { regexFilter: '^https?://.*', requestDomains: uniq.slice(i, i + CHUNK), resourceTypes: ['main_frame'] }
      });
    }
    return rules;
  }

                                                                                 
                                                                             
    
                                                                        
                                                                         
                                                                
                                                                            
                                                                       
                                                                          
                                                                            
  function buildPathRedirectRules(entries, targetUrl) {
    const out = []; const seen = new Set();
    for (const e of entries || []) {
      if (out.length >= MAX_PATH_RULES) break;
      const h = e && typeof e.h === 'string' ? e.h.trim().toLowerCase() : '';
      const p = e && typeof e.p === 'string' ? e.p.trim() : '';
                                                                            
                                                                        
                                                                           
      if (!h || !HOST_LABELS_RE.test(h) || !p.startsWith('/') || p.length > 200) continue;
      const key = h + p; if (seen.has(key)) continue; seen.add(key);
      out.push({
        id: PATH_BASE + out.length, priority: 2,
        action: { type: 'redirect', redirect: { regexSubstitution: targetUrl + '#\\0' } },
        condition: { regexFilter: '^https?://' + escapeRegex(h) + escapeRegex(p) + '(?:[/?#]|$)', requestDomains: [h], resourceTypes: ['main_frame'] }
      });
    }
    return out;
  }

                                                                          
                                                                      
  function isTenantApex(d) { return !!(C && C.isTenantApex && C.isTenantApex(d)); }
                                                                              
  function buildAllowRules(domains, stats) {
    const all = [...new Set([...(domains || [])].filter(Boolean).map((d) => String(d).toLowerCase()))];
    const kept = all.filter((d) => !isTenantApex(d));
    if (stats && typeof stats === 'object') stats.skipped = all.length - kept.length;
    const uniq = kept.slice(0, MAX_ALLOW);
    return uniq.map((d, i) => ({
      id: ALLOW_BASE + i, priority: 3, action: { type: 'allow' },
      condition: { urlFilter: '||' + d + '^', resourceTypes: ['main_frame', 'sub_frame'] }
    }));
  }

                                                                               
  function exemptDomains(settings, now) {
    const s = settings || {}; const t = typeof now === 'number' ? now : Date.now();
    const out = [];
    for (const d of Array.isArray(s.allowlist) ? s.allowlist : []) if (typeof d === 'string' && d) out.push(d);
    const ps = (s.pausedSites && typeof s.pausedSites === 'object') ? s.pausedSites : {};
    for (const d of Object.keys(ps)) { const until = Number(ps[d]); if (Number.isFinite(until) && until > t) out.push(d); }
    return [...new Set(out.map((d) => d.toLowerCase()))];
  }

  return {
    BLOCK_BASE, REDIRECT_BASE, ALLOW_BASE, HOT_BASE, PATH_BASE, RANGE, CHUNK, MAX_ALLOW, MAX_PATH_RULES,
    domainOfFilter, inRange, escapeRegex, buildBlockRules, buildRedirectRules, buildPathRedirectRules, buildAllowRules, exemptDomains, isTenantApex
  };
});
