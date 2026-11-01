                                                        
  
                                                                                           
                                                                                     
                                                                           
                                                                           
                                                            
                                                                              
                                                                           
                                                                            
                                                                           
  
                                                                             
                                                    
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSReview = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const DAY = 86400000;
  const INSTALL_AGE_DAYS = 7;                                                     
  const THREATS_THRESHOLD = 2;                                                                                                
  const SNOOZE_DAYS = 90;                                       
  const MAX_ASKS = 2;                                                                                   
                                                                                
                                                                               

  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

                       
                                                                                                 
                           
                                   
                                                                                         
                                                                 
  function eligible(input) {
    const o = input || {};
    if (num(o.threatsBlocked) < THREATS_THRESHOLD) return false;
    const now = typeof o.now === 'number' && Number.isFinite(o.now) ? o.now : Date.now();
    if (now - num(o.installedAt) < INSTALL_AGE_DAYS * DAY) return false;
    if (o.state === 'pending') return true;
    if (o.state === 'snoozed') return now >= num(o.snoozeUntil) && num(o.asks) < MAX_ASKS;
    return false;                                        
  }

                                                                               
                                                                                
                                                                                
                                                                              
                                                                            
                                                                           
                                                                       
                                                                             
                                                                         
  function isChromeFromManifest(manifest) {
    return !(manifest && manifest.browser_specific_settings);
  }

                                                                             

                                                                        
                                                                            
                                                                             
                                                                            
                                                                             
                                                     
  function shouldShowCard(isEligible, level) {
    return !!isEligible && level !== 'dangerous' && level !== 'suspicious';
  }

  return { DAY, INSTALL_AGE_DAYS, THREATS_THRESHOLD, SNOOZE_DAYS, MAX_ASKS, eligible, isChromeFromManifest, shouldShowCard };
});
