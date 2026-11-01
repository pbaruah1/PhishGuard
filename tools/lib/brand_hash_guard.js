                                                                          
                                                                         
                                                                            
                                                                           
  
                                                                        
                                                                          
                                                                     
                                                                    
                                                                       
                                                                          
                                                                          
                                       
'use strict';
const { hamming } = require('../../engine/detection/image_hash');

function isSuperset(supDomains, subDomains) {
  const sup = new Set(supDomains || []);
  return (subDomains || []).length > 0 && (subDomains || []).every((d) => sup.has(d));
}

                                      
                                                                                
                                                                               
                                                                      
                                                                          
                                          
function resolveCollisions(brands, domainsByKey, minDist = 12) {
  domainsByKey = domainsByKey || {};
                                                                         
                                                                      
                                                                             
                                                                            
  const snapshot = (brands || []).map((b) => ({
    key: b.key, hashes: [...new Set(b.hashes || [])].slice(0, 4), entries: b.entries || null
  }));

  const dropSet = new Set();                         
  const dropped = [];
  const addDrop = (key, hash, reason, other) => {
    const id = key + '\u0000' + hash;
    if (dropSet.has(id)) return;
    dropSet.add(id);
    dropped.push({ brand: key, hash, reason, other });
  };

  for (let i = 0; i < snapshot.length; i++) {
    for (let j = i + 1; j < snapshot.length; j++) {
      const A = snapshot[i];
      const B = snapshot[j];
      if (A.key === B.key) continue;
      const domA = domainsByKey[A.key] || [];
      const domB = domainsByKey[B.key] || [];
      const aSupersetOfB = isSuperset(domA, domB);
      const bSupersetOfA = isSuperset(domB, domA);
      for (const ha of A.hashes) {
        for (const hb of B.hashes) {
          if (hamming(ha, hb) >= minDist) continue;
          if (aSupersetOfB && !bSupersetOfA) {
            addDrop(B.key, hb, 'sub-brand', A.key);                                       
          } else if (bSupersetOfA && !aSupersetOfB) {
            addDrop(A.key, ha, 'sub-brand', B.key);                                       
          } else {
            addDrop(A.key, ha, 'ambiguous', B.key);
            addDrop(B.key, hb, 'ambiguous', A.key);
          }
        }
      }
    }
  }

  const result = [];
  for (const b of snapshot) {
    const keep = b.hashes.filter((h) => !dropSet.has(b.key + '\u0000' + h)).slice(0, 4);
    if (keep.length) {
      const out = { key: b.key, hashes: keep };
      if (b.entries) {
        const keepSet = new Set(keep);
        out.entries = b.entries.filter((e) => keepSet.has(e.hash));
      }
      result.push(out);
    }
  }
  return { brands: result, dropped };
}

module.exports = { resolveCollisions, isSuperset };
