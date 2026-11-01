                                                                                 
                                                                                 
(function () {
  'use strict';
  if (window.__phishguardClipboardHook) return;
  window.__phishguardClipboardHook = true;

  const analyze = (t) => {
    try {
      return (window.PhishGuard && window.PhishGuard.analyzeClipboardWrite)
        ? window.PhishGuard.analyzeClipboardWrite(t) : { level: 'safe', reasons: [] };
    } catch (_) { return { level: 'safe', reasons: [] }; }
  };
  function emit(verdict, sample) {
    if (verdict.level === 'safe') return;
    try {
      window.dispatchEvent(new CustomEvent('phishguard:clipboard-alert', {
        detail: {
          level: verdict.level, reasons: verdict.reasons, sample: String(sample || '').slice(0, 120),
                                                                                
                                                                            
                                                                              
                                                                             
                                                       
                                                                              
                                                                               
                                                                        
                                                                   
          userGesture: !!(navigator.userActivation && navigator.userActivation.isActive)
        }
      }));
    } catch (_) {}
  }

                                      
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = function (text) { emit(analyze(text), text); return orig(text); };
    }
  } catch (_) {}

                                  
  document.addEventListener('copy', (ev) => {
    try {
      const cd = ev.clipboardData;
      if (!cd) return;
      const setData = cd.setData.bind(cd);
      cd.setData = function (type, data) { if (/text/.test(type)) emit(analyze(data), data); return setData(type, data); };
    } catch (_) {}
  }, true);
})();
