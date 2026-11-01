                                                                                     
                                                                            
                                                                         
(function (root, factory) {
  const req = typeof require === 'function';
  const mod = factory(req ? require('./dnr_rules') : root.SSDnr, req ? require('../core/constants') : root.PhishGuard);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSHot = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function (D, C) {
  'use strict';
                                                                            
                                                                       
                                                                        
                                                                         
                                                                         
                                 
  const MAX_DOMAINS = 20000;
  const WINDOW_MS = 48 * 3600 * 1000;
                                                                          
                                                                              
                                                                        
  const MAX_STALE_MS = 48 * 3600 * 1000;
                                                                            
                                                                            
                                                                        
                              
  const MAX_TRUSTED_HOSTS = 25;
  const MAX_GROWTH_FACTOR = 3;
                                                                             
                                                                          
                                                                        
                                        
  const GROWTH_FLOOR = 2000;
  const MAX_GROWTH_REJECTS = 3;
  const HOST_RE = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;

  const BRANDS = new Set(C.KNOWN_BRAND_REGISTRABLES || []);
  const verifiedNs = typeof C.isVerifiedNamespace === 'function' ? C.isVerifiedNamespace : () => false;
  const isTenantHost = (h) => (C.TENANT_PLATFORMS || []).some((p) => h.endsWith('.' + p));

                                                                             
                                                                            
                                                                       
                                                                         
                                                                          
                                                                          
                  
  function isProtectedHost(h) {
    if (verifiedNs(h)) return true;
    const bare = h.replace(/^www\./, '');
    if (isTenantHost(bare) || C.registrableDomain(bare) !== bare) return false;
    return BRANDS.has(bare) || C.isSafeHost(bare);
  }

  function parseHot(json, now) {
    const t = typeof now === 'number' ? now : Date.now();
    if (!json || typeof json !== 'object' || json.v !== 1) return null;
    if (typeof json.generatedAt !== 'number' || !Array.isArray(json.domains)) return null;
    const minNow = Math.floor(t / 60000), minCutoff = Math.floor((t - WINDOW_MS) / 60000);
    const norm = (e) => {
      if (!e || typeof e.h !== 'string') return null;
      const h = e.h.trim().toLowerCase().replace(/\.+$/, '');
      if (!HOST_RE.test(h)) return null;
      const tt = typeof e.t === 'number' ? e.t : minNow;
      if (tt < minCutoff) return null;
      return { h, s: typeof e.s === 'string' ? e.s : '', t: tt };
    };
    const domains = json.domains.map(norm).filter(Boolean).sort((a, b) => b.t - a.t).slice(0, MAX_DOMAINS);
    const paths = (Array.isArray(json.paths) ? json.paths : []).map((e) => { const n = norm(e); return n && typeof e.p === 'string' && e.p.startsWith('/') ? Object.assign(n, { p: e.p }) : null; }).filter(Boolean);
                                                                   
                                                                         
                                                                          
                                             
    const removed = (Array.isArray(json.removed) ? json.removed : []).filter((h) => typeof h === 'string').map((h) => h.toLowerCase());
    return { v: 1, generatedAt: json.generatedAt, ttlMinutes: typeof json.ttlMinutes === 'number' ? json.ttlMinutes : 360, domains, paths, removed };
  }

  function isStale(hot, now) {
    const t = typeof now === 'number' ? now : Date.now();
    return !hot || (t - hot.generatedAt) > hot.ttlMinutes * 60000;
  }

                                                                          
  function isExpired(hot, now) {
    const t = typeof now === 'number' ? now : Date.now();
    return !hot || (t - hot.generatedAt) > Math.max(hot.ttlMinutes * 60000, MAX_STALE_MS);
  }

                                                                           
                                                                           
                                                                         
                                                                      
    
                                                                          
                                                                        
                                                                        
                                                                         
                                                                            
                                                                            
                                                                             
                               
  function guardHot(hot, settings, now) {
    const t = typeof now === 'number' ? now : Date.now();
    const dropped = { apex: 0, exempt: 0, safe: 0, brand: 0, verified: 0, expired: 0, aged: 0 };
    if (isExpired(hot, t)) { dropped.expired = (hot ? hot.domains.length + hot.paths.length : 0); return { domains: [], paths: [], dropped }; }
    const exempt = new Set(D.exemptDomains(settings || {}, t));
    const brands = new Set(C.KNOWN_BRAND_REGISTRABLES || []);
    const verified = typeof C.isVerifiedNamespace === 'function' ? C.isVerifiedNamespace : () => false;
    const platforms = new Set(C.TENANT_PLATFORMS || []);
    const suffixes = new Set(C.MULTI_LABEL_SUFFIXES || []);
                                                                               
                                                                    
                                                                         
                                                                          
                                                                           
                                                                            
                                                                  
    const isApex = (h) => {
      const labels = h.split('.').filter(Boolean);
      if (labels.length < 2) return true;                                          
      if (platforms.has(h)) return true;                                                              
      if (suffixes.has(h)) return true;                                       
      const parts = C.registrableParts(h);
      return h === parts.suffix;                                                         
    };
                                                                        
                                                                             
                                                                     
                                                                           
                                                                 
    const isExempt = (h, reg) => {
      if (exempt.has(reg) && !D.isTenantApex(reg)) return true;
      const labels = h.split('.');
      for (let i = 0; i < labels.length - 1; i++) {
        const cand = labels.slice(i).join('.');
        if (exempt.has(cand) && !D.isTenantApex(cand)) return true;
      }
      return false;
    };
    const keep = (h) => {
      const reg = C.registrableDomain(h);
      if (isApex(h)) { dropped.apex++; return false; }
      if (isExempt(h, reg)) { dropped.exempt++; return false; }
      if (verified(h)) { dropped.verified++; return false; }
                                                                               
                                                                               
                                                                               
                                     
      const bare = h.replace(/^www\./, '');
      if (isTenantHost(h) && !platforms.has(bare) && !isProtectedHost(h)) return true;
      if (brands.has(reg) || brands.has(h)) { dropped.brand++; return false; }
      if (C.isSafeHost(h)) { dropped.safe++; return false; }
      return true;
    };
                                                                              
                                                                           
    const minCutoff = Math.floor((t - WINDOW_MS) / 60000);
    const fresh = (e) => { if (typeof e.t === 'number' && e.t < minCutoff) { dropped.aged++; return false; } return true; };
    const domains = hot.domains.filter(fresh).map((d) => d.h).filter(keep);
    const paths = hot.paths.filter(fresh).filter((p) => keep(p.h)).map((p) => ({ h: p.h, p: p.p }));
    return { domains, paths, dropped };
  }

                                                                        
                                                                             
                                                                             
                                                                            
                                                                          
                                                                                               
                                                                         
  function assessHot(parsed, prevCount, growthRejects) {
    const domains = parsed && parsed.domains ? parsed.domains : [];
    const n = domains.length;
    const trusted = domains.filter((d) => d && typeof d.h === 'string' && isProtectedHost(d.h)).length;
    if (trusted > MAX_TRUSTED_HOSTS) return { ok: false, reason: 'trusted-hosts' };
    if (prevCount > 0 && n > Math.max(prevCount, GROWTH_FLOOR) * MAX_GROWTH_FACTOR && !((growthRejects || 0) >= MAX_GROWTH_REJECTS)) return { ok: false, reason: 'growth' };
    return { ok: true, reason: '' };
  }

                                                                          
                                                                              
                                                                             
  function guardOtaFilters(filters) {
    const kept = []; let dropped = 0;
    for (const f of filters || []) {
      const h = D.domainOfFilter(f);
      if (h && isProtectedHost(h)) { dropped++; continue; }
      kept.push(f);
    }
    return { kept, dropped };
  }

  function hotRules(guarded, targetUrl) {
    return [...D.buildRedirectRules(guarded.domains, targetUrl, D.HOT_BASE), ...D.buildPathRedirectRules(guarded.paths, targetUrl)];
  }
  function hotRuleIds(existing) {
    return (existing || []).filter((r) => D.inRange(r.id, D.HOT_BASE) || D.inRange(r.id, D.PATH_BASE)).map((r) => r.id);
  }
  return { MAX_DOMAINS, WINDOW_MS, MAX_STALE_MS, MAX_TRUSTED_HOSTS, MAX_GROWTH_FACTOR, GROWTH_FLOOR, MAX_GROWTH_REJECTS, parseHot, isStale, isExpired, guardHot, assessHot, isProtectedHost, guardOtaFilters, hotRules, hotRuleIds };
});
