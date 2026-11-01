                                                     
  
                                                                        
                                                                        
                                                                        
                                                                           
                                                                                     
                                                                          
                                             
  
                                                                             
                                  
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSFooter = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                              
                                                                            
                                                                             
  const ROTATION = ['trust', 'support'];

                                                                           
                                                                          
                                                 
  function nextVariant(stored) {
    const i = ROTATION.indexOf(stored);
    return i === -1 ? ROTATION[0] : ROTATION[(i + 1) % ROTATION.length];
  }

  return { ROTATION, nextVariant };
});
