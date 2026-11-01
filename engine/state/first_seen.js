                                                                                
                                                           
                                                                     
                                                                         
                                                           
  
                                                                
                                                                           
                                                                           
                                                                           
                                                                           
                                                                         
                                                                            
                                                                
  
                                                                         
                                                                            
                                                              
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSFirstSeen = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const CAP = 2000;
  const SUPPRESS_AFTER_DAYS = 30;
  const SUPPRESS_AFTER_MS = SUPPRESS_AFTER_DAYS * 24 * 3600 * 1000;

                                                                        
                                                                           
                                                                           
                                            
  function normalize(list) {
    const out = [];
    for (const e of (Array.isArray(list) ? list : [])) {
      if (!Array.isArray(e) || e.length !== 2) continue;
      const [hash, ts] = e;
      if (typeof hash !== 'string' || !hash) continue;
      if (typeof ts !== 'number' || !Number.isFinite(ts) || ts < 0) continue;
      out.push([hash, ts]);
    }
    return out;
  }

                                                                          
                                                                   
                                                                             
                                                                          
                                                                      
                                                                            
                           
                                          
  function touch(list, hostHash, now) {
    const clean = normalize(list);
    const idx = clean.findIndex(([h]) => h === hostHash);
    let firstSeenAt;
    let rest;
    if (idx === -1) {
      firstSeenAt = now;
      rest = clean;
    } else {
      firstSeenAt = clean[idx][1];
      rest = clean.slice(0, idx).concat(clean.slice(idx + 1));
    }
    const next = rest.concat([[hostHash, firstSeenAt]]).slice(-CAP);
    return { list: next, firstSeenAt, isNew: idx === -1 };
  }

                                                                        
                                                                        
                                                                           
                                                                       
                                                     
  function isEstablished(list, hostHash, now) {
    const clean = normalize(list);
    const entry = clean.find(([h]) => h === hostHash);
    if (!entry) return false;
    return (now - entry[1]) >= SUPPRESS_AFTER_MS;
  }

  return { CAP, SUPPRESS_AFTER_DAYS, SUPPRESS_AFTER_MS, normalize, touch, isEstablished };
});
