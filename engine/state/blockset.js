                                                                   
  
                                                                       
                                                                             
                                                                           
                                                                            
                                                                             
                                                             
  
                                                                           
                                                                              
                                                                              
                                                                             
                                                                            
                                                                      
                                                                      
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.Blockset = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const RECORD_SIZE = 5;
  const DELTA_HEADER_SIZE = 8;                                              

                                                                      
  function recordValueAt(view, off) {
    return view.getUint32(off, false) * 256 + view.getUint8(off + 4);
  }
                                                                          
                                                
  function writeRecordValue(view, off, value) {
    view.setUint32(off, Math.floor(value / 256), false);
    view.setUint8(off + 4, value % 256);
  }

                                                                           
                                                                           
                                                                              
                                                                        
  function hash40FromBytes(bytes) {
    if (!bytes || bytes.length < RECORD_SIZE) throw new RangeError('hash40FromBytes needs at least 5 bytes');
    let v = 0;
    for (let i = 0; i < RECORD_SIZE; i++) v = v * 256 + (bytes[i] & 0xff);
    return v;
  }

                                                                             
                                                                          
                                                                            
                                                                     
  function shardByte(hash40) { return Math.floor(hash40 / 0x100000000); }

                                                                        
                                                          
  function open(buf) {
    if (!(buf instanceof ArrayBuffer)) throw new TypeError('open() requires an ArrayBuffer');
    if (buf.byteLength % RECORD_SIZE !== 0) throw new RangeError('buffer length is not a multiple of ' + RECORD_SIZE);
    return { buf, view: new DataView(buf), count: buf.byteLength / RECORD_SIZE };
  }

                                                                                 
  function has(set, hash40) {
    let lo = 0, hi = set.count - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const v = recordValueAt(set.view, mid * RECORD_SIZE);
      if (v === hash40) return true;
      if (v < hash40) lo = mid + 1; else hi = mid - 1;
    }
    return false;
  }

                                                                       
                                                                          
                                                  
  function values(set) {
    const out = new Array(set.count);
    for (let i = 0; i < set.count; i++) out[i] = recordValueAt(set.view, i * RECORD_SIZE);
    return out;
  }

  function count(set) { return set.count; }

                                                                          
                                                    
  function isSorted(set) {
    for (let i = 1; i < set.count; i++) {
      if (recordValueAt(set.view, (i - 1) * RECORD_SIZE) >= recordValueAt(set.view, i * RECORD_SIZE)) return false;
    }
    return true;
  }

                                                                              
                                                                            
                                       
  function binarySearchValue(sortedArr, target) {
    let lo = 0, hi = sortedArr.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (sortedArr[mid] === target) return true;
      if (sortedArr[mid] < target) lo = mid + 1; else hi = mid - 1;
    }
    return false;
  }

                                                                             
                                                                     
  function parseDelta(deltaBuf) {
    if (!(deltaBuf instanceof ArrayBuffer)) throw new TypeError('parseDelta() requires an ArrayBuffer');
    if (deltaBuf.byteLength < DELTA_HEADER_SIZE) throw new RangeError('delta buffer shorter than its header');
    const dv = new DataView(deltaBuf);
    const addedCount = dv.getUint32(0, false);
    const removedCount = dv.getUint32(4, false);
    const addedStart = DELTA_HEADER_SIZE;
    const removedStart = addedStart + addedCount * RECORD_SIZE;
    const expectedLen = removedStart + removedCount * RECORD_SIZE;
    if (deltaBuf.byteLength !== expectedLen) {
      throw new RangeError(`delta buffer length ${deltaBuf.byteLength} does not match header (expected ${expectedLen})`);
    }
    const added = new Array(addedCount);
    for (let i = 0; i < addedCount; i++) added[i] = recordValueAt(dv, addedStart + i * RECORD_SIZE);
    const removed = new Array(removedCount);
    for (let i = 0; i < removedCount; i++) removed[i] = recordValueAt(dv, removedStart + i * RECORD_SIZE);
    return { added, removed };
  }

                                                                         
                                                                            
                                                                              
                                                                             
                                                                            
  function applyDelta(baseBuf, deltaBuf) {
    if (!(baseBuf instanceof ArrayBuffer)) throw new TypeError('applyDelta() requires a base ArrayBuffer');
    const baseView = new DataView(baseBuf);
    const baseCount = baseBuf.byteLength / RECORD_SIZE;
    const { added, removed } = parseDelta(deltaBuf);

    const kept = [];
    for (let i = 0; i < baseCount; i++) {
      const v = recordValueAt(baseView, i * RECORD_SIZE);
      if (!binarySearchValue(removed, v)) kept.push(v);
    }

                                                                                
    const merged = [];
    let i = 0, j = 0;
    while (i < kept.length && j < added.length) {
      if (kept[i] === added[j]) { merged.push(kept[i]); i++; j++; }
      else if (kept[i] < added[j]) merged.push(kept[i++]);
      else merged.push(added[j++]);
    }
    while (i < kept.length) merged.push(kept[i++]);
    while (j < added.length) merged.push(added[j++]);

    const out = new ArrayBuffer(merged.length * RECORD_SIZE);
    const outView = new DataView(out);
    for (let k = 0; k < merged.length; k++) writeRecordValue(outView, k * RECORD_SIZE, merged[k]);
    return out;
  }

                                                                      
                                                                         
                                                                           
                                                                              
                                                                            
                                                           
  function findExact(entries, hostname) {
    if (!Array.isArray(entries) || !hostname) return null;
    for (const e of entries) {
      if (e && e.d === hostname) return e;
    }
    return null;
  }

  return {
    RECORD_SIZE, DELTA_HEADER_SIZE,
    hash40FromBytes, shardByte,
    open, has, values, count, isSorted,
    binarySearchValue, parseDelta, applyDelta,
    findExact
  };
});
