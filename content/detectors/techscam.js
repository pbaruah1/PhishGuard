                                                                             
                                                     
(function () {
  'use strict';
  if (window.__phishguardTechHook) return;
  window.__phishguardTechHook = true;

  let dialogFloodCount = 0;
  let fullscreenOnLoad = false;
  let beforeUnloadCount = 0;
  let alarmAudio = false;
  let escaped = false;                                                   

  function emit() {
    try {
      window.dispatchEvent(new CustomEvent('phishguard:techscam-signal', {
        detail: { dialogFloodCount, fullscreenOnLoad, beforeUnloadCount, alarmAudio }
      }));
    } catch (_) {}
  }

                                                                         
                                                                       
  function checkAlarmAudio() {
    try {
      if (alarmAudio) return;
      const media = document.querySelectorAll('audio, video');
      for (const m of media) {
        if ((!m.paused || m.autoplay) && (m.loop || !m.hasAttribute('controls'))) { alarmAudio = true; break; }
      }
      if (!alarmAudio && window.speechSynthesis && window.speechSynthesis.speaking) alarmAudio = true;
      if (alarmAudio) emit();
    } catch (_) {}
  }
  setTimeout(checkAlarmAudio, 1500);
  setTimeout(checkAlarmAudio, 4000);

                                                                               
                                                                              
  for (const name of ['alert', 'confirm', 'prompt']) {
    const orig = window[name] ? window[name].bind(window) : null;
    if (!orig) continue;
    window[name] = function () {
      dialogFloodCount++;
      emit();
      if (dialogFloodCount <= 2) { try { return orig.apply(null, arguments); } catch (_) {} }
      return name === 'confirm' ? false : (name === 'prompt' ? null : undefined);
    };
  }

                                               
  document.addEventListener('fullscreenchange', () => {
    if (document.fullscreenElement) { fullscreenOnLoad = true; emit(); }
  }, true);

                                                                  
                                                                            
                                                                           
                                                                            
                                                                     
                                                          
  function unloadAllowed() {
    try {
      if (document.permissionsPolicy && typeof document.permissionsPolicy.allowsFeature === 'function') {
        return document.permissionsPolicy.allowsFeature('unload');
      }
    } catch (_) {}
    return true;
  }
  const canUnload = unloadAllowed();

                                                                               
                                                                              
                                                                            
                                                                       
                                                                   
                                                                           
                                                                       
                                                                             
                                                                         
                                              
  const origAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type) {
    if (type === 'beforeunload' || type === 'unload') {
      if (type === 'beforeunload') beforeUnloadCount++;
      if (escaped) return undefined;                    
      if (!canUnload) return undefined;                                                        
    }
    return origAdd.apply(this, arguments);
  };

                                                                           
                                                                                
  window.addEventListener('phishguard:techscam-escape', () => {
    escaped = true;
    try { if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen(); } catch (_) {}
    try { window.onbeforeunload = null; document.body && (document.body.onbeforeunload = null); } catch (_) {}
    try { window.speechSynthesis && window.speechSynthesis.cancel(); } catch (_) {}
    try { document.querySelectorAll('audio, video').forEach((m) => { m.pause(); m.loop = false; }); } catch (_) {}
  });

  if (document.readyState !== 'loading') emit();
  else document.addEventListener('DOMContentLoaded', emit);
})();
