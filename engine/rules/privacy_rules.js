(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                          
    
                                                                               
                                                                                
                                                                                
                                                                  
    
                                                                              
                                                                            
                                                                              
                                                                

                                                                        
                                                                       
                                                            
  function md5(str) {
    function rl(n, c) { return (n << c) | (n >>> (32 - c)); }
    function add(a, b) { return (a + b) & 0xffffffff; }
    function cmn(q, a, b, x, s, t) { return add(rl(add(add(a, q), add(x, t)), s), b); }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 128) bytes.push(c);
      else if (c < 2048) { bytes.push(192 | (c >> 6), 128 | (c & 63)); }
      else { bytes.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63)); }
    }
    const n = bytes.length;
    const words = [];
    for (let i = 0; i < n; i++) words[i >> 2] = (words[i >> 2] || 0) | (bytes[i] << ((i % 4) * 8));
    words[n >> 2] = (words[n >> 2] || 0) | (0x80 << ((n % 4) * 8));
    const bits = n * 8;
    const len = (((n + 8) >> 6) + 1) * 16;
    while (words.length < len) words.push(0);
    words[len - 2] = bits & 0xffffffff;
    words[len - 1] = Math.floor(bits / 0x100000000);
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    const T = [-680876936, -389564586, 606105819, -1044525330, -176418897, 1200080426, -1473231341, -45705983, 1770035416, -1958414417, -42063, -1990404162, 1804603682, -40341101, -1502002290, 1236535329, -165796510, -1069501632, 643717713, -373897302, -701558691, 38016083, -660478335, -405537848, 568446438, -1019803690, -187363961, 1163531501, -1444681467, -51403784, 1735328473, -1926607734, -378558, -2022574463, 1839030562, -35309556, -1530992060, 1272893353, -155497632, -1094730640, 681279174, -358537222, -722521979, 76029189, -640364487, -421815835, 530742520, -995338651, -198630844, 1126891415, -1416354905, -57434055, 1700485571, -1894986606, -1051523, -2054922799, 1873313359, -30611744, -1560198380, 1309151649, -145523070, -1120210379, 718787259, -343485551];
    for (let i = 0; i < words.length; i += 16) {
      const oa = a, ob = b, oc = c, od = d;
      for (let j = 0; j < 64; j++) {
        const g = j < 16 ? j : j < 32 ? (5 * j + 1) % 16 : j < 48 ? (3 * j + 5) % 16 : (7 * j) % 16;
        const s = S[(j >> 4) * 4 + (j % 4)];
        const fn = j < 16 ? ff : j < 32 ? gg : j < 48 ? hh : ii;
        const t = fn(a, b, c, d, words[i + g] || 0, s, T[j]);
        a = d; d = c; c = b; b = t;
      }
      a = add(a, oa); b = add(b, ob); c = add(c, oc); d = add(d, od);
    }
    function hex(x) { let s = ''; for (let i = 0; i < 4; i++) s += ('0' + ((x >> (i * 8)) & 0xff).toString(16)).slice(-2); return s; }
    return hex(a) + hex(b) + hex(c) + hex(d);
  }

                                                                            
                                                                        
                                                                      
  function findLeak(haystack, needles) {
    if (!haystack || !needles) return null;
    const h = String(haystack).toLowerCase();
    for (const kind of ['plain', 'md5', 'sha1', 'sha256']) {
      const list = needles[kind] || [];
      for (const v of list) if (v && v.length >= 6 && h.indexOf(v.toLowerCase()) !== -1) return kind;
    }
    return null;
  }

                                                                             
                                                                               
                                                                           
  const FP_SURFACES = ['canvasReadback', 'webglParams', 'audioFingerprint', 'fontProbe', 'navigatorEnum', 'rectMeasure'];
  function scoreFingerprint(counts) {
    const c = counts || {};
    const distinct = FP_SURFACES.filter((k) => (c[k] || 0) > 0).length;
    const heavy = (c.canvasReadback || 0) >= 1 && (c.fontProbe || 0) >= 20;
                                                                            
                                                        
    const isFp = distinct >= 3 || heavy || (c.canvasReadback || 0) >= 1 && (c.webglParams || 0) >= 5;
    return { isFp, distinct, surfaces: FP_SURFACES.filter((k) => (c[k] || 0) > 0) };
  }

                                                                               
                                                                                     
  function isSameSite(originA, originB, registrable) {
    try { const ha = new URL(originA).hostname, hb = new URL(originB).hostname; const r = typeof registrable === 'function' ? registrable : (h) => h; return r(ha) === r(hb); } catch (_) { return false; }
  }

  return { privacy: { md5, findLeak, scoreFingerprint, FP_SURFACES, isSameSite } };
});
