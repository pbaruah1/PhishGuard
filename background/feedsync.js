                                                                            
  
                                                                               
                                                                               
                                                                              
                                                                             
                                                                               
                                                                        
  
                                                                          
                                                                              
                                                    
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSFeedSync = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const WARN_REFRESH_MIN_MS = 7 * 24 * 3600 * 1000;                                                 
  const FULL_TIMEOUT_MS = 30000;                                                          
  const DELTA_TIMEOUT_MS = 15000;                                    

  function withTimeout(opts, timeoutMs) {
    if (timeoutMs && typeof AbortSignal !== 'undefined' && AbortSignal.timeout) opts.signal = AbortSignal.timeout(timeoutMs);
    return opts;
  }

                                                                               
                                                                          
                                                                           
                                                                       
  async function fetchBufFromBases(bases, filename, timeoutMs, fetchFn) {
    const f = fetchFn || fetch;
    for (const base of bases) {
      if (!base) continue;
      try {
        const res = await f(base + filename, withTimeout({ cache: 'no-cache' }, timeoutMs));
        if (!res.ok) continue;
        return await res.arrayBuffer();
      } catch (_) {                         }
    }
    return null;
  }

                                                                               
  async function fetchJsonFromBases(bases, filename, timeoutMs, fetchFn) {
    const f = fetchFn || fetch;
    for (const base of bases) {
      if (!base) continue;
      try {
        const res = await f(base + filename, withTimeout({ cache: 'no-cache' }, timeoutMs));
        if (!res.ok) continue;
        const text = await res.text();
        let data;
        try { data = JSON.parse(text); } catch (_) { continue; }
        return { data, text };
      } catch (_) {                         }
    }
    return null;
  }

     
                                       
                                                                                       
      
                                                                 
                                                              
                                                                              
                                                                                   
                                                                            
                                                                           
                                                                             
     
  async function syncFeed({ meta, rec, deps }) {
    const { fetchBuf, fetchJson, sha256Hex, applyDelta, save } = deps;
    const now = deps.now || Date.now;
    let cur = Object.assign({}, rec);
    const partial = [];
    const out = { blockChanged: false, warnChanged: false, riskChanged: false, nrdChanged: false };

                                                                           
                                                           
    async function commit(patch) {
      const next = Object.assign({}, cur, patch, { urls: meta.urls });
      await save(next);
      cur = next;
    }

                                                                                
    if (meta.version !== rec.version) {
      try {
        let blockBuf = null;
        if (rec.blockBuf && meta.prev && meta.prev === rec.version) {
          const deltaBuf = await fetchBuf(`delta-${rec.version}.bin`, DELTA_TIMEOUT_MS);
          if (deltaBuf && meta.sha256 && meta.sha256.deltaFromPrev && (await sha256Hex(deltaBuf)) === meta.sha256.deltaFromPrev) {
            try { blockBuf = applyDelta(rec.blockBuf, deltaBuf); } catch (_) {                                                   }
          }
        }
        if (!blockBuf) {
                                                                                
                                                                               
          const fullBuf = await fetchBuf('set40.bin', FULL_TIMEOUT_MS);
          if (fullBuf && meta.sha256 && meta.sha256.set40 && (await sha256Hex(fullBuf)) === meta.sha256.set40) blockBuf = fullBuf;
        }
                                                                               
        if (blockBuf) { await commit({ version: meta.version, blockBuf }); out.blockChanged = true; }
        else partial.push('block');
      } catch (_) { partial.push('block'); }
    }

                                                                                     
    if (!cur.warnBuf || now() - (cur.warnUpdatedAt || 0) >= WARN_REFRESH_MIN_MS) {
      try {
        const buf = await fetchBuf('warn40.bin', FULL_TIMEOUT_MS);
                                                                                      
        if (buf && (!(meta.sha256 && meta.sha256.warn40) || (await sha256Hex(buf)) === meta.sha256.warn40)) {
          await commit({ warnBuf: buf, warnUpdatedAt: now() }); out.warnChanged = true;
        } else partial.push('warn');
      } catch (_) { partial.push('warn'); }
    }

                                                                      
    if (!cur.riskTables || now() - (cur.riskUpdatedAt || 0) >= WARN_REFRESH_MIN_MS) {
      try {
        const fetched = await fetchJson('risk.json', FULL_TIMEOUT_MS);
        if (fetched && fetched.data && typeof fetched.data === 'object' &&
            (!(meta.sha256 && meta.sha256.risk) || (await sha256Hex(new TextEncoder().encode(fetched.text))) === meta.sha256.risk)) {
          await commit({ riskTables: fetched.data, riskUpdatedAt: now() }); out.riskChanged = true;
        } else partial.push('risk');
      } catch (_) { partial.push('risk'); }
    }

                                                                                  
    if (!cur.nrdBuf || now() - (cur.nrdUpdatedAt || 0) >= WARN_REFRESH_MIN_MS) {
      try {
        const buf = await fetchBuf('nrd.bloom', FULL_TIMEOUT_MS);
        if (buf && (!(meta.nrd && meta.nrd.sha256) || (await sha256Hex(buf)) === meta.nrd.sha256)) {
          await commit({ nrdBuf: buf, nrdUpdatedAt: now() }); out.nrdChanged = true;
        } else partial.push('nrd');
      } catch (_) { partial.push('nrd'); }
    }

    return Object.assign(out, { rec: cur, version: cur.version || '', partial });
  }

  return { WARN_REFRESH_MIN_MS, FULL_TIMEOUT_MS, DELTA_TIMEOUT_MS, fetchBufFromBases, fetchJsonFromBases, syncFeed };
});
