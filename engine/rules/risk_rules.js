                                                                              
                                                                        
                                                                              
  
                                                             
                                                                             
                                                                    
                                                                        
                                                             
                                                                         
                                                                           
                                                                            
                                                                               
                                                                
                              
(function (root, factory) {
  const req = typeof require === 'function';
  const mod = factory(req ? require('../core/constants') : root.PhishGuard);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C) {
  'use strict';

  const { registrableParts } = C;

                                                                              
                                                             
  function abusedTldWeight(host, tlds) {
    if (!tlds || typeof tlds !== 'object') return null;
    const parts = registrableParts(String(host || '').toLowerCase());
    if (!parts.suffix) return null;
    const tld = '.' + parts.suffix.split('.').pop();
    const w = tlds[tld];
    return typeof w === 'number' ? { tld, weight: w } : null;
  }

                                                                          
                                                                            
                                                                           
  function hash32FromBytes(bytes) {
    if (!bytes || bytes.length < 4) throw new RangeError('hash32FromBytes needs at least 4 bytes');
    let v = 0;
    for (let i = 0; i < 4; i++) v = v * 256 + (bytes[i] & 0xff);
    return v >>> 0;
  }

                                                                             
                                                                    
                                                                           
                                                                   
  function matchHostingRisk(hash32, dyndnsSet, hostersSet) {
    if (typeof hash32 !== 'number' || Number.isNaN(hash32)) return null;
    if (dyndnsSet && typeof dyndnsSet.has === 'function' && dyndnsSet.has(hash32)) return 'dyndns';
    if (hostersSet && typeof hostersSet.has === 'function' && hostersSet.has(hash32)) return 'hoster';
    return null;
  }

  return { abusedTldWeight, hash32FromBytes, matchHostingRisk };
});
