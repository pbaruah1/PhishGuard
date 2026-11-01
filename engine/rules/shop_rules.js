(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                               
                                                                              
                                                                            
                                                                        
                                                                             
                                                               
    
                                                                  
                                                                           
                                                                           
                                                                           
                                                                               
                                                                              
                                                          
                                                                          
                                                                    
    
                                                                               
                                                                
                                                     
                                                                               
                                                                         
  const WEIGHT = { offPlatformPay: 3, countdownReset: 2, fakeScarcity: 1, badgeHotlink: 1, missingContact: 1 };

  function scoreShop(input) {
    const s = input || {};
    if (!s.isStorefront) return { level: 'none', flags: [], score: 0 };
    const flags = [];
    let score = 0;
    const add = (code) => { flags.push({ code }); score += WEIGHT[code]; };
    if (s.countdownReset) add('countdownReset');
    if (s.offPlatformPay) add('offPlatformPay');
    if ((s.fakeScarcity || 0) > 0) add('fakeScarcity');
    if (s.badgeHotlink) add('badgeHotlink');
    if (s.missingContact) add('missingContact');
                                                                            
                                          
    let level = 'none';
    if (score >= 3) level = 'suspicious';
    else if (score >= 1) level = 'note';
    return { level, flags, score };
  }

  return { scoreShop };
});
