                                                                                    
                                                                              
                                                                         
                                                                      
                                                                        
                                                                 
  
                                                                            
                                                                       
                                                                       
                                     
  
                                                                          
                                                                         
                                                                         
                                                                          
                                                                          
                                                                         
                                                                        
                                                                         
                                                                      
                                                            
  
                                                                           
                                                                     
                                                                       
                                                                            
                                                                          
                                                                           
                                                                          
                                          
(function (root, factory) {
  const req = typeof require === 'function';
  const mod = factory(req ? require('../core/constants') : root.PhishGuard);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C) {
  'use strict';

  const { registrableParts } = C;

  const LONG_LABEL_MIN = 22;
  const DEEP_CHAIN_MIN = 4;
                                                                            
  const SHORTENER_HOSTS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 'is.gd', 'ow.ly', 'tiny.cc', 'bc.vc',
    'bit.do', 'ity.im', 'lc.chat', 's2r.co', 'soo.gd'
  ];

                                                                            
                                                                             
                                                                            
                                                            
  function labelsBelowRegistrable(host) {
    const h = String(host || '').toLowerCase().replace(/\.+$/, '');
    const parts = registrableParts(h);
    if (!parts.suffix) return [];                                           
    const labels = h.split('.').filter(Boolean);
    const domainLabelCount = parts.domain.split('.').length;
    return labels.slice(0, Math.max(0, labels.length - domainLabelCount));
  }

                                                                            
                                                                            
                               
  function hasLongLabel(host, max) {
    const m = max || LONG_LABEL_MIN;
    const labels = String(host || '').toLowerCase().replace(/\.+$/, '').split('.').filter(Boolean);
    return labels.some((l) => l.length >= m);
  }

                                                                 
  function shortenerHost(host) {
    const h = String(host || '').toLowerCase();
    return SHORTENER_HOSTS.find((d) => h === d || h.endsWith('.' + d)) || null;
  }

                                                                              
                                                                               
                                                                    
                                                                              
                                                                        
                                                                         
                                                                           
                                                                            
                                                                           
                                                                      
                                                                     
                                                   
  const RANDOM_PATH_RE = /^\/[A-Za-z0-9_-]{5,12}\/?$/;
  const RANDOM_QUERY_RE = /^\/?\?[A-Za-z0-9]{5,10}$/;
  function gatewaySignal(nav) {
    const n = nav || {};
    const none = { score: 0, reasons: [] };
    if (!(n.redirectCount > 0) || typeof n.originalUrl !== 'string' || !n.landingHost) return none;
    let u;
    try { u = new URL(n.originalUrl); } catch (_) { return none; }
    const from = u.hostname.toLowerCase();
    const to = String(n.landingHost).toLowerCase();
    if (registrableParts(from).domain === registrableParts(to).domain) return none;
    if (C.isSafeHost && C.isSafeHost(from)) return none;
    if (!(RANDOM_PATH_RE.test(u.pathname) || RANDOM_QUERY_RE.test(u.pathname + (u.search || '')))) return none;
    return { score: 0.25, reasons: [{ code: 'gatewayRedirect', kind: 'link', params: [from] }] };
  }

                                                                            
                                                                                  
                                                  
  function scoreSiteSignals(host) {
    const reasons = [];
    let score = 0;
    if (labelsBelowRegistrable(host).length >= DEEP_CHAIN_MIN) {
      score += 0.20;
      reasons.push({ code: 'deepSubdomainChain', kind: 'link' });
    }
    if (hasLongLabel(host)) {
      score += 0.15;
      reasons.push({ code: 'longHostLabel', kind: 'link' });
    }
    const shortener = shortenerHost(host);
    if (shortener) {
      score += 0.20;
      reasons.push({ code: 'shortenerHost', kind: 'link', params: [shortener] });
    }
    return { score: Math.max(0, Math.min(1, score)), reasons };
  }

  return {
    LONG_LABEL_MIN, DEEP_CHAIN_MIN, SHORTENER_HOSTS,
    labelsBelowRegistrable, hasLongLabel, shortenerHost, scoreSiteSignals,
    gatewaySignal
  };
});
