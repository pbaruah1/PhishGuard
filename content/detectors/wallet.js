                                                                           
                                                                              
(function () {
  'use strict';
  if (window.__phishguardWalletHook) return;
  window.__phishguardWalletHook = true;

  const pending = new Map();
  const timers = new Map();                                                                 
  let seq = 0;
  const analyze = (req) => {
    try {
      return (window.PhishGuard && window.PhishGuard.analyzeWalletRequest)
        ? window.PhishGuard.analyzeWalletRequest(req) : { level: 'safe', reasons: [] };
    } catch (_) { return { level: 'safe', reasons: [] }; }
  };

  window.addEventListener('phishguard:wallet-decision', (e) => {
    const d = e.detail || {};
    const p = pending.get(d.id);
    if (p) { pending.delete(d.id); clearTimeout(timers.get(d.id)); timers.delete(d.id); p(!!d.allow); }
  });
                                                                              
                                                                          
                                                                    
                                                                             
                                                                
  window.addEventListener('phishguard:wallet-ack', (e) => {
    const d = e.detail || {};
    if (pending.has(d.id) && timers.has(d.id)) {
      clearTimeout(timers.get(d.id));
                                                                          
                                                                              
                                                                       
      timers.set(d.id, setTimeout(() => { timers.delete(d.id); if (pending.has(d.id)) { const p = pending.get(d.id); pending.delete(d.id); p(false); } }, 5 * 60000));
    }
  });

  function confirm(verdict) {
    return new Promise((resolve) => {
      const id = ++seq;
      pending.set(id, resolve);
      try {
        window.dispatchEvent(new CustomEvent('phishguard:wallet-confirm', {
          detail: { id, level: verdict.level, reasons: verdict.reasons }
        }));
      } catch (_) { pending.delete(id); resolve(true); return; }
                                                                            
      timers.set(id, setTimeout(() => { timers.delete(id); if (pending.has(id)) { pending.delete(id); resolve(true); } }, 8000));
    });
  }

  function wrap(provider) {
    if (!provider || provider.__phishguardWrapped || typeof provider.request !== 'function') return;
    provider.__phishguardWrapped = true;
    const orig = provider.request.bind(provider);
                                                                        
                                                
    provider.request = async function (args) {
      const verdict = analyze(args);
      if (verdict.level === 'dangerous' || verdict.level === 'suspicious') {
        const allow = await confirm(verdict);
        if (!allow) {
          const err = new Error('PhishGuard blocked a risky wallet request.');
          err.code = 4001;                          
          throw err;
        }
      }
      return orig(args);
    };
  }

  if (window.ethereum) wrap(window.ethereum);
                                       
  window.addEventListener('ethereum#initialized', () => wrap(window.ethereum), { once: true });
                                                                       
                                                                        
                                                                            
  window.addEventListener('eip6963:announceProvider', (e) => {
    try { wrap(e && e.detail && e.detail.provider); } catch (_) {}
  });
  try { window.dispatchEvent(new Event('eip6963:requestProvider')); } catch (_) {}
  let tries = 0;
  const iv = setInterval(() => { if (window.ethereum) wrap(window.ethereum); if (++tries > 20) clearInterval(iv); }, 250);
})();
