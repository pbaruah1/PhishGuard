                                                                                 
  
                                                                               
                                                                                
                                                                            
                                                                        
                                                                          
  
                                                                       
                                              
                                            
                                               
                                                      
                                            
                                                                          
                                                                         
                                                                             
                                                                         
  
                                                                       
                                                                             
                                                                          
                                                                            
                                                                           
                                                              
                                                                          
                                                 
                                                 
                                                                        
                                                                       
                                                                          
                                                                             
                                                       
                                                                          
                                                      
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.Bloom = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const MAGIC = 'NRDB';
  const HEADER_LEN = 16;

                                                         
                                                                           
                                                                      
                                                                        
                                
  function parseHeader(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    if (u8.length < HEADER_LEN) throw new RangeError('nrd.bloom buffer shorter than the 16-byte header');
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const magic = String.fromCharCode(u8[0], u8[1], u8[2], u8[3]);
    if (magic !== MAGIC) throw new RangeError(`bad magic: expected ${MAGIC}, got ${magic}`);
    const version = dv.getUint8(4);
    const k = dv.getUint8(5);
    const n = dv.getUint32(8, false);
    const mBits = dv.getUint32(12, false);
    const expectedLen = HEADER_LEN + Math.ceil(mBits / 8);
    if (u8.length !== expectedLen) {
      throw new RangeError(`nrd.bloom length ${u8.length} does not match header (expected ${expectedLen})`);
    }
    return { version, k, n, mBits, bits: u8.subarray(HEADER_LEN) };
  }

                                                                           
                                                                            
                                                                 
  function indicesFor(hashBytes, k, mBits) {
    if (!hashBytes || hashBytes.length < 8) throw new RangeError('indicesFor needs at least 8 digest bytes');
    let h1 = 0;
    for (let i = 0; i < 4; i++) h1 = h1 * 256 + (hashBytes[i] & 0xff);
    let h2 = 0;
    for (let i = 4; i < 8; i++) h2 = h2 * 256 + (hashBytes[i] & 0xff);
    if (h2 === 0) h2 = 1;
    const out = new Array(k);
    for (let i = 0; i < k; i++) out[i] = (h1 + i * h2) % mBits;
    return out;
  }

  function testBit(bits, idx) {
    return (bits[idx >> 3] & (1 << (7 - (idx & 7)))) !== 0;
  }

                                                                             
                                                                       
                                                                          
                                                                
  function test(parsed, hashBytes) {
    if (!parsed || !parsed.bits || !parsed.mBits || !parsed.k) return false;
    let idxs;
    try { idxs = indicesFor(hashBytes, parsed.k, parsed.mBits); } catch (_) { return false; }
    for (const idx of idxs) {
      if (!testBit(parsed.bits, idx)) return false;
    }
    return true;
  }

  return { MAGIC, HEADER_LEN, parseHeader, indicesFor, testBit, test };
});
