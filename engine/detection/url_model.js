                                                                                   
                                                                           
(function (root, factory) {
  const mod = factory(root);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (root) {
  'use strict';

  let MODEL = null;                                                                        

  function currentModel() {
    if (MODEL) return MODEL;
    const ss = root.PhishGuard;
    if (ss && ss.URL_MODEL && Array.isArray(ss.URL_MODEL.trees)) MODEL = ss.URL_MODEL;
    return MODEL;
  }
  function setUrlModel(m) { MODEL = m || null; }
  function isAvailable() { return !!currentModel(); }

  function evalTree(nodes, x) {
    let i = 0;
    for (let guard = 0; guard < 64; guard++) {
      const n = nodes[i];
      if (!n) return 0;                                                               
      if (n[2] === -1) return n[4];                     
      const v = x[n[0]];
      const goLeft = Number.isNaN(v) ? n[5] === 1 : v <= n[1];
      i = goLeft ? n[2] : n[3];
    }
    return 0;                                                  
  }

  function predictUrlProb(vector, model) {
    const m = model || currentModel();
    if (!m) return NaN;
    let z = typeof m.baseline === 'number' && !Number.isNaN(m.baseline) ? m.baseline : 0;
    for (const t of m.trees) z += evalTree(t.nodes, vector);
    const p = 1 / (1 + Math.exp(-z));
    return Math.max(0, Math.min(1, p));
  }

                                                                              
  async function predict(vector) {
    try {
      if (!isAvailable()) return null;
      const p = predictUrlProb(Array.from(vector));
      return Number.isNaN(p) ? null : p;
    } catch (_) { return null; }
  }

  return { predictUrlProb, predict, isAvailable, setUrlModel, _resetForTest: () => { MODEL = null; } };
});
