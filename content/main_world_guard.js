                                                                                
                                                                                
                                                         
(function () {
  'use strict';
  if (window.__phishguardMainGuard) return;
  window.__phishguardMainGuard = true;

                                                                               
                                                                             
                                                                             
                                                                              
  if (typeof HTMLFormElement !== 'undefined' && HTMLFormElement.prototype && typeof HTMLFormElement.prototype.submit === 'function') {
    const nativeSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function () {
      let allowed = true;
      try {
        allowed = this.dispatchEvent(new CustomEvent('phishguard:formsubmit', { bubbles: true, cancelable: true }));
      } catch (_) {}
      if (allowed) return nativeSubmit.apply(this, arguments);
    };
  }

                                                                            
  function emitNav() { try { window.dispatchEvent(new CustomEvent('phishguard:navigate')); } catch (e) {} }
  try {
    const nativeAttachShadow = Element.prototype.attachShadow;
    if (typeof nativeAttachShadow === 'function' && !nativeAttachShadow.__phishGuardWrapped) {
      const wrappedAttachShadow = function (init) {
        const shadow = nativeAttachShadow.apply(this, arguments);
        if (init && init.mode === 'open') {
          try { this.dispatchEvent(new CustomEvent('phishguard:shadow-root-created', { bubbles: true, composed: true })); } catch (_) {}
        }
        return shadow;
      };
      wrappedAttachShadow.__phishGuardWrapped = true;
      Element.prototype.attachShadow = wrappedAttachShadow;
    }
  } catch (_) {}
  for (const m of ['pushState', 'replaceState']) {
    const orig = history[m];
    if (typeof orig === 'function') {
      history[m] = function () { const r = orig.apply(this, arguments); emitNav(); return r; };
    }
  }
  window.addEventListener('popstate', emitNav);
})();
