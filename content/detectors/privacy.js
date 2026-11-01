                                                                            
                                                                           
                                                                              
                                                     
                                                                               
                                                                           
                                                                     
                                                                    
                                                                              
                                                      
(function () {
  'use strict';
  if (window.__phishguardPrivacyHook) return;
  window.__phishguardPrivacyHook = true;

  const P = (window.PhishGuard && window.PhishGuard.privacy) || null;
  if (!P) return;                                                    

                                                                                
  function callerOrigin() {
    try {
      const stack = (new Error()).stack || '';
      const lines = stack.split('\n');
      for (const ln of lines) {
        const m = ln.match(/https?:\/\/[^\s):]+/);
        if (m) {
          const u = new URL(m[0]);
          if (u.origin !== location.origin) return u.origin;                           
          if (!callerOrigin._self) callerOrigin._self = u.origin;
        }
      }
    } catch (_) {}
    return callerOrigin._self || location.origin;
  }

  function emit(name, detail) { try { window.dispatchEvent(new CustomEvent(name, { detail })); } catch (_) {} }

                                          
  let armed = false;                                                 
  const needles = { plain: [], md5: [], sha1: [], sha256: [] };
  const leaked = new Set();                                         

  function armFrom(value) {
    const v = String(value || '').trim().toLowerCase();
    if (v.length < 6 || needles.plain.indexOf(v) !== -1) return;
                                                                            
                                                                
    needles.plain.push(v);
    armed = true;
    try { needles.md5.push(P.md5(v)); } catch (_) {}
    addHashes(v);
  }
  async function addHashes(v) {
    try {
      const enc = new TextEncoder().encode(v);
      if (window.crypto && crypto.subtle) {
        const [s1, s256] = await Promise.all([
          crypto.subtle.digest('SHA-1', enc).catch(() => null),
          crypto.subtle.digest('SHA-256', enc).catch(() => null)
        ]);
        const hex = (buf) => buf ? Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('') : null;
        const h1 = hex(s1), h256 = hex(s256);
        if (h1) needles.sha1.push(h1);
        if (h256) needles.sha256.push(h256);
      }
    } catch (_) {}
  }

  document.addEventListener('input', (e) => {
    const t = e && e.target;
    if (!t || !t.tagName) return;
    const type = (t.getAttribute && (t.getAttribute('type') || '')).toLowerCase();
    const name = ((t.getAttribute && (t.getAttribute('name') || t.getAttribute('autocomplete') || t.id)) || '').toLowerCase();
    if (type === 'email' || type === 'tel' || /email|e-mail|phone|mobile|tel/.test(name)) {
      if (typeof t.value === 'string' && t.value.indexOf('@') !== -1 || type === 'tel' || /phone|mobile|tel/.test(name)) armFrom(t.value);
    }
  }, true);

  function inspectOutbound(where, dest, payloads) {
    if (!armed) return;
    let destOrigin = location.origin;
    try { destOrigin = new URL(dest, location.href).origin; } catch (_) {}
    const reg = window.PhishGuard && window.PhishGuard.registrableDomain;
    if (destOrigin === location.origin || P.isSameSite(location.origin, destOrigin, reg)) return;                                            
    for (const p of payloads) {
      let dec = p;
      try { dec = decodeURIComponent(String(p).replace(/\+/g, ' ')); } catch (_) { dec = p; }
      const kind = P.findLeak(p, needles) || P.findLeak(dec, needles);
      if (kind) {
        const key = destOrigin + '|' + kind;
        if (leaked.has(key)) return;
        leaked.add(key);
        let destHost = destOrigin; try { destHost = new URL(dest, location.href).hostname; } catch (_) {}
        emit('phishguard:leaky-form', { destHost, destOrigin, kind, where });
        return;
      }
    }
  }

          
  try {
    const of = window.fetch;
    if (of) window.fetch = function (input, init) {
      try {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        const body = (init && typeof init.body === 'string') ? init.body : '';
        inspectOutbound('fetch', url, [url, body]);
      } catch (_) {}
      return of.apply(this, arguments);
    };
  } catch (_) {}
        
  try {
    const oo = XMLHttpRequest.prototype.open, os = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (m, u) { this.__ssURL = u; return oo.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function (b) { try { inspectOutbound('xhr', this.__ssURL || '', [this.__ssURL || '', typeof b === 'string' ? b : '']); } catch (_) {} return os.apply(this, arguments); };
  } catch (_) {}
               
  try {
    if (navigator.sendBeacon) {
      const ob = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = function (url, data) { try { inspectOutbound('beacon', url, [url, typeof data === 'string' ? data : '']); } catch (_) {} return ob(url, data); };
    }
  } catch (_) {}
                            
  try {
    const desc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    if (desc && desc.set) {
      Object.defineProperty(HTMLImageElement.prototype, 'src', {
        configurable: true, enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) { try { inspectOutbound('img', v, [String(v)]); } catch (_) {} return desc.set.call(this, v); }
      });
    }
  } catch (_) {}

                                             
  const fpCounts = {};                                             
  let fpReported = false;
  let fpBudget = 400;                                                          
  function bump(surface) {
    if (fpReported || fpBudget <= 0) return;
    fpBudget--;
    const o = callerOrigin();
    const c = fpCounts[o] || (fpCounts[o] = {});
    c[surface] = (c[surface] || 0) + 1;
    scheduleFpCheck();
  }
  let fpTimer = null;
  function scheduleFpCheck() {
    if (fpReported || fpTimer) return;
    fpTimer = setTimeout(() => {
      fpTimer = null;
      for (const origin of Object.keys(fpCounts)) {
        const r = P.scoreFingerprint(fpCounts[origin]);
        if (r.isFp) { fpReported = true; emit('phishguard:fingerprint', { origin, surfaces: r.surfaces }); return; }
      }
    }, 800);
  }
  function wrap(obj, name, surface, guard) {
    try {
      const orig = obj[name];
      if (typeof orig !== 'function') return;
      obj[name] = function () { try { if (!guard || guard.apply(this, arguments)) bump(surface); } catch (_) {} return orig.apply(this, arguments); };
    } catch (_) {}
  }
  try { wrap(HTMLCanvasElement.prototype, 'toDataURL', 'canvasReadback'); } catch (_) {}
  try { wrap(HTMLCanvasElement.prototype, 'toBlob', 'canvasReadback'); } catch (_) {}
  try { wrap(CanvasRenderingContext2D.prototype, 'getImageData', 'canvasReadback'); } catch (_) {}
  try { wrap(CanvasRenderingContext2D.prototype, 'measureText', 'fontProbe'); } catch (_) {}
  try { if (window.WebGLRenderingContext) wrap(WebGLRenderingContext.prototype, 'getParameter', 'webglParams'); } catch (_) {}
  try { if (window.OfflineAudioContext) wrap(OfflineAudioContext.prototype, 'startRendering', 'audioFingerprint'); } catch (_) {}
  try { wrap(Element.prototype, 'getBoundingClientRect', 'rectMeasure', function () { return false; }); } catch (_) {}                                                          

                                                
  try {
    if (window.Notification && Notification.requestPermission) {
      const orig = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = function () {
        try { emit('phishguard:notify-request', { origin: location.origin }); } catch (_) {}
        return orig.apply(this, arguments);
      };
    }
  } catch (_) {}
})();
